"""Coverage-ledger helpers used by Phantom's orchestration quality gates."""

from __future__ import annotations

import hashlib
import re
from typing import Any


COVERAGE_STATUSES = frozenset(
    {"planned", "running", "confirmed", "ruled_out", "blocked", "not_tested"}
)
COVERAGE_TERMINAL_STATUSES = frozenset({"confirmed", "ruled_out", "blocked", "not_tested"})
COVERAGE_PRIORITIES = frozenset({"required", "recommended", "optional"})
PAYLOAD_CRAFTER_STATUSES = frozenset({"planned", "spawned", "not_required"})

# These are deliberately broad *lanes*, not vulnerability findings.  Every
# lane gets one bounded discovery owner after recon; the owner can rule the
# lane out when the discovered surface does not support it.  This keeps the
# high-recall behaviour of the original orchestration without making the LLM
# guess whether a whole family should be skipped.
DISCOVERY_LANE_SPECS: dict[str, dict[str, Any]] = {
    "authentication": {
        "name": "Authentication, Session & Token Discovery",
        "skills": [
            "vulnerabilities/authentication_jwt",
            "vulnerabilities/weak_password_detection",
            "vulnerabilities/timing_attacks",
        ],
        "families": ["authentication", "session", "auth_bypass", "token_handling"],
    },
    "authorization": {
        "name": "Authorization & Object Access Discovery",
        "skills": [
            "vulnerabilities/idor",
            "vulnerabilities/broken_function_level_authorization",
            "vulnerabilities/mass_assignment",
        ],
        "families": ["idor", "broken_function_level_authorization", "privilege_escalation"],
    },
    "injection": {
        "name": "Web Input & Injection Discovery",
        "skills": [
            "vulnerabilities/sql_injection",
            "vulnerabilities/xss",
            "vulnerabilities/nosql_injection",
            "vulnerabilities/ssti",
        ],
        "families": ["sql_injection", "xss", "nosql_injection", "ssti", "xxe"],
    },
    "state_change": {
        "name": "State-Changing Workflow & Abuse Discovery",
        "skills": [
            "vulnerabilities/business_logic",
            "vulnerabilities/csrf",
            "vulnerabilities/api_abuse",
            "vulnerabilities/race_conditions",
        ],
        "families": ["business_logic", "csrf", "api_abuse", "race_conditions"],
    },
    "api": {
        "name": "API Route & Protocol Discovery",
        "skills": [
            "custom/api_spec_testing",
            "vulnerabilities/api_abuse",
            "protocols/graphql",
            "protocols/websocket_security",
        ],
        "families": [
            "api_mapping",
            "api_abuse",
            "graphql",
            "websocket_security",
            "webhook_security",
        ],
    },
    "server_side": {
        "name": "Server-Side Fetch, File & Parser Discovery",
        "skills": [
            "vulnerabilities/ssrf",
            "vulnerabilities/path_traversal_lfi_rfi",
            "vulnerabilities/xxe",
            "vulnerabilities/insecure_deserialization",
            "vulnerabilities/insecure_file_uploads",
        ],
        "families": [
            "ssrf",
            "path_traversal_lfi_rfi",
            "xxe",
            "insecure_deserialization",
            "insecure_file_uploads",
        ],
    },
    "client_side": {
        "name": "Client-Side & Browser Sink Discovery",
        "skills": [
            "vulnerabilities/xss",
            "vulnerabilities/browser_security",
            "vulnerabilities/prototype_pollution",
        ],
        "families": ["xss", "dom_xss", "browser_security", "prototype_pollution"],
    },
    "error_disclosure": {
        "name": "Error Handling & Information Disclosure Discovery",
        "skills": ["vulnerabilities/information_disclosure"],
        "families": ["information_disclosure", "error_handling", "debug_exposure"],
    },
    "technology": {
        "name": "Technology & Configuration Surface Discovery",
        "skills": ["tooling/httpx", "custom/api_spec_testing"],
        "families": ["technology_detection", "configuration", "api_spec_testing"],
    },
}

_PAYLOAD_CONTEXT_SKILLS = {
    "sql_injection": "vulnerabilities/sql_injection",
    "xss": "vulnerabilities/xss",
    "dom_xss": "vulnerabilities/browser_security",
    "nosql_injection": "vulnerabilities/nosql_injection",
    "ssti": "vulnerabilities/ssti",
    "ssrf": "vulnerabilities/ssrf",
    "path_traversal_lfi_rfi": "vulnerabilities/path_traversal_lfi_rfi",
    "xxe": "vulnerabilities/xxe",
    "insecure_deserialization": "vulnerabilities/insecure_deserialization",
    "insecure_file_uploads": "vulnerabilities/insecure_file_uploads",
    "websocket_security": "protocols/websocket_security",
    "webhook_security": "vulnerabilities/webhook_security",
    "api_abuse": "vulnerabilities/api_abuse",
}

_COMPLEX_PAYLOAD_FAMILIES = frozenset(_PAYLOAD_CONTEXT_SKILLS)
_ERROR_MARKERS = re.compile(
    r"(?:stack\s*trace|exception|traceback|debug|internal server error|\b5\d\d\b|"
    r"verbose error|sql error|error message)",
    re.IGNORECASE,
)

_BROAD_TASK_MARKERS = (
    "recon",
    "reconnaissance",
    "attack surface",
    "map the",
    "map all",
    "enumerate",
    "discover",
    "systematic",
    "comprehensive",
    "all endpoints",
    "all vulnerabilities",
)

_HTTP_METHOD_RE = re.compile(
    r"\b(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b", re.IGNORECASE
)
_PATH_TOKEN_RE = re.compile(
    r"(?:https?://[^\s,;)>\]]+|/[A-Za-z0-9][^\s,;)>\]]+)",
    re.IGNORECASE,
)


def _clean(value: Any) -> str:
    return " ".join(str(value or "").split()).strip()


def _clean_list(value: Any) -> list[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, dict):
        values = list(value)
    elif isinstance(value, list):
        values = value
    else:
        return []
    cleaned: list[str] = []
    for item in values:
        if isinstance(item, dict):
            item = (
                item.get("name")
                or item.get("parameter")
                or item.get("path")
                or item.get("route")
                or item.get("value")
                or item
            )
        value_text = _clean(item)
        if value_text:
            cleaned.append(value_text)
    return list(dict.fromkeys(cleaned))


def stable_coverage_id(*, title: str, surface: str, category: str) -> str:
    """Return a stable, non-target-specific id for a planned test item."""
    source = "|".join(_clean(value).casefold() for value in (title, surface, category))
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:12]
    return f"cov-{digest}"


def normalize_coverage_item(raw: dict[str, Any], *, agent_id: str | None = None) -> dict[str, Any]:
    """Normalize one model-supplied coverage item without inventing evidence."""
    title = _clean(raw.get("title"))
    surface = _clean(raw.get("surface"))
    category = _clean(raw.get("category")).casefold()
    if not title:
        raise ValueError("coverage item title is required")
    if not surface:
        raise ValueError("coverage item surface is required")
    if not category:
        raise ValueError("coverage item category is required")

    status = _clean(raw.get("status") or "planned").casefold()
    if status not in COVERAGE_STATUSES:
        raise ValueError(f"invalid coverage status: {status}")
    priority = _clean(raw.get("priority") or "required").casefold()
    if priority not in COVERAGE_PRIORITIES:
        raise ValueError(f"invalid coverage priority: {priority}")

    coverage_id = _clean(raw.get("coverage_id")) or stable_coverage_id(
        title=title,
        surface=surface,
        category=category,
    )
    if not re.fullmatch(r"cov-[a-f0-9]{12}", coverage_id):
        raise ValueError("coverage_id must be a generated value such as cov-0123456789ab")

    families = raw.get("test_families") or []
    if not isinstance(families, list):
        raise ValueError("test_families must be an array")
    test_families = [_clean(item).casefold() for item in families if _clean(item)]
    if not test_families:
        raise ValueError("coverage item must declare at least one test family")

    item: dict[str, Any] = {
        "coverage_id": coverage_id,
        "title": title,
        "category": category,
        "surface": surface,
        "test_families": list(dict.fromkeys(test_families)),
        "priority": priority,
        "status": status,
    }
    discovery_lane = _clean(raw.get("discovery_lane")).casefold()
    if discovery_lane:
        item["discovery_lane"] = discovery_lane
    coverage_kind = _clean(raw.get("coverage_kind")).casefold()
    if coverage_kind:
        item["coverage_kind"] = coverage_kind
    for field in ("surface_kind", "route", "method", "parameter", "auth_context", "planner_source"):
        value = _clean(raw.get(field))
        if value:
            item[field] = value
    technologies = _clean_list(raw.get("technologies"))
    if technologies:
        item["technologies"] = technologies
    requires_payload_crafter = raw.get("requires_payload_crafter")
    if isinstance(requires_payload_crafter, bool):
        item["requires_payload_crafter"] = requires_payload_crafter
    payload_status = _clean(raw.get("payload_crafter_status")).casefold()
    if payload_status:
        if payload_status not in PAYLOAD_CRAFTER_STATUSES:
            raise ValueError(f"invalid payload_crafter_status: {payload_status}")
        item["payload_crafter_status"] = payload_status
    payload_agent_id = _clean(raw.get("payload_crafter_agent_id"))
    if payload_agent_id:
        item["payload_crafter_agent_id"] = payload_agent_id
    for field in ("evidence", "notes"):
        value = _clean(raw.get(field))
        if value:
            item[field] = value
    if agent_id:
        item["updated_by"] = agent_id
    return item


def validate_agent_assignment(
    *,
    agent_type: str | None,
    task: str,
    coverage_ids: list[str],
    existing_items: list[dict[str, Any]],
) -> str | None:
    """Prevent specialized roles from being used as broad discovery agents."""
    if agent_type is None:
        return None

    known_ids = {
        str(item.get("coverage_id"))
        for item in existing_items
        if isinstance(item, dict) and item.get("coverage_id")
    }
    unknown = sorted(set(coverage_ids) - known_ids)
    if unknown:
        return f"Unknown coverage_id(s): {unknown}. Record the coverage item before assigning it."

    if agent_type in {"web_validator", "payload_crafter", "reporting_analyst"} and not coverage_ids:
        return (
            f"agent_type={agent_type} requires at least one concrete coverage_id; "
            "specialized agents cannot be used for unbounded discovery"
        )
    if agent_type == "web_validator" and len(coverage_ids) > 3:
        return "web_validator may cover at most three closely related coverage items"

    lowered_task = _clean(task).casefold()
    if agent_type in {"web_validator", "payload_crafter", "reporting_analyst"}:
        broad = [marker for marker in _BROAD_TASK_MARKERS if marker in lowered_task]
        if broad and agent_type != "reporting_analyst":
            return (
                f"agent_type={agent_type} is narrowly scoped, but the task is broad "
                f"({', '.join(broad[:3])}); use a default discovery agent first"
            )
    return None


def _records(value: Any) -> list[dict[str, Any]]:
    """Turn common recon shapes into small, defensive endpoint records."""
    if isinstance(value, dict):
        return [value]
    if not isinstance(value, list):
        return []
    records: list[dict[str, Any]] = []
    for value_item in value:
        if isinstance(value_item, dict):
            records.append(value_item)
        elif _clean(value_item):
            records.append({"path": _clean(value_item)})
    return records


def _first(record: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and _clean(value):
            return _clean(value)
    return ""


def _endpoint_records(surface_map: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    global_parameters = _clean_list(surface_map.get("parameters"))
    for key in ("endpoints", "routes", "api_routes", "forms", "paths", "inputs"):
        for record in _records(surface_map.get(key)):
            path = _first(record, "path", "url", "endpoint", "route", "action", "location")
            if path or key in {"forms", "inputs"}:
                if global_parameters and not _record_parameters(record):
                    record = {**record, "parameters": global_parameters}
                records.append({**record, "_source": key})
    return records


def _record_parameters(record: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("parameters", "params", "inputs", "fields", "query_parameters", "body_parameters"):
        values.extend(_clean_list(record.get(key)))
    return list(dict.fromkeys(values))


def _path_parameters(path: str) -> list[str]:
    """Extract parameter names from a URL path without interpreting values."""
    names = re.findall(r"[?&]([A-Za-z0-9_.-]+)(?:=|&|$)", path)
    for group in re.findall(r"\{([^{}]+)\}", path):
        names.extend(re.findall(r"[A-Za-z_][A-Za-z0-9_.-]*", group))
    return list(dict.fromkeys(_clean(name) for name in names if _clean(name)))


def _line_parameters(line: str, path: str, path_end: int) -> list[str]:
    """Extract named body/form fields stated next to a discovered route."""
    names = _path_parameters(path)
    parameter_segments: list[str] = []
    parameter_segments.extend(
        match.group(1)
        for match in re.finditer(
            r"\b(?:params?|parameters?|fields?)\b\s*[:=]?\s*([^;]+)",
            line,
            re.IGNORECASE,
        )
    )

    tail = line[path_end:].lstrip()
    if tail.startswith("("):
        closing = tail.find(")")
        if closing > 1:
            content = tail[1:closing]
            parts = [part.strip().strip("{}") for part in content.split(",")]
            if len(parts) > 1 and all(
                re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", part) for part in parts
            ):
                parameter_segments.append(",".join(parts))

    for segment in parameter_segments:
        for part in re.split(r"[,|]", segment):
            match = re.search(r"\b([A-Za-z_][A-Za-z0-9_.-]*)\b", part)
            if match:
                name = match.group(1)
                if name.casefold() not in {"params", "parameters", "fields", "inputs"}:
                    names.append(name)
    return list(dict.fromkeys(_clean(name) for name in names if _clean(name)))


def _text_blocks(value: Any) -> list[str]:
    """Collect text from common recon-note and inventory shapes."""
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, list):
        blocks: list[str] = []
        for entry in value:
            blocks.extend(_text_blocks(entry))
        return blocks
    if isinstance(value, dict):
        blocks: list[str] = []
        for key in ("content", "body", "text", "summary", "notes", "evidence"):
            if key in value:
                blocks.extend(_text_blocks(value[key]))
        return blocks
    return []


def _endpoint_records_from_text(text_blocks: list[str]) -> list[dict[str, Any]]:
    """Recover generic endpoint records from recon prose or Markdown notes."""
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for block in text_blocks:
        for raw_line in block.splitlines():
            line = _clean(raw_line)
            if not line:
                continue
            matches = list(_PATH_TOKEN_RE.finditer(line))
            for match in matches:
                if match.start() and line[match.start() - 1] == "<":
                    continue
                token = match.group(0).rstrip(".,:;`'\"()")
                if "<" in token:
                    token = token.split("<", 1)[0]
                token = token.rstrip(".,:;`'\"()")
                if token.startswith("//"):
                    continue
                if not token or "*" in token:
                    continue
                prefix = line[: match.start()]
                is_bullet = bool(re.match(r"^\s*[-*]\s+", line))
                has_method = bool(
                    re.search(
                        r"(?:^|[\s(:>-])(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s*$",
                        prefix,
                        re.I,
                    )
                )
                has_action = bool(
                    re.search(
                        r"(?:post|posts|call|calls|action|redirect|redirects|to)\s*$",
                        prefix,
                        re.I,
                    )
                )
                if not (is_bullet or has_method or has_action):
                    continue
                context = f"{line[max(0, match.start() - 32):match.end() + 32]}"
                methods = _HTTP_METHOD_RE.findall(context)
                method = methods[-1].upper() if methods else "GET"
                key = (method, token.casefold())
                if key in seen:
                    continue
                seen.add(key)
                parameters = _line_parameters(line, token, match.end())
                record: dict[str, Any] = {
                    "path": token,
                    "method": method,
                    "notes": line,
                }
                if parameters:
                    record["parameters"] = parameters
                lower = line.casefold()
                if token.casefold().startswith(("/api", "http://", "https://")) and (
                    "/api" in token.casefold() or "json" in lower or "swagger" in lower
                ):
                    record["kind"] = "api"
                elif method in {"POST", "PUT", "PATCH", "DELETE"} or "form" in lower:
                    record["kind"] = "form"
                records.append(record)
    return records


def _expand_surface_map(surface_map: dict[str, Any]) -> dict[str, Any]:
    """Preserve structured recon data and supplement it with shared note text."""
    expanded = dict(surface_map)
    existing_observations = _clean_list(surface_map.get("observations"))
    text_blocks: list[str] = []
    for key in ("recon_notes", "notes", "inventory", "attack_surface", "observations"):
        text_blocks.extend(_text_blocks(surface_map.get(key)))

    extracted = _endpoint_records_from_text(text_blocks)
    if extracted:
        expanded["endpoints"] = [*expanded.get("endpoints", [])] if isinstance(
            expanded.get("endpoints"), list
        ) else []
        expanded["endpoints"].extend(extracted)
    if text_blocks:
        expanded["observations"] = list(dict.fromkeys([*existing_observations, *text_blocks]))
    return expanded


def _record_text(record: dict[str, Any]) -> str:
    values: list[str] = []
    for key in (
        "path",
        "url",
        "endpoint",
        "route",
        "action",
        "kind",
        "type",
        "auth",
        "auth_context",
        "notes",
        "evidence",
        "content_type",
    ):
        values.append(_clean(record.get(key)))
    values.extend(_record_parameters(record))
    values.extend(_clean_list(record.get("technologies")))
    return " ".join(value for value in values if value)


def _surface_path(record: dict[str, Any], base_url: str) -> str:
    path = _first(record, "path", "url", "endpoint", "route", "action", "location") or "/"
    if base_url and path.startswith("/"):
        return f"{base_url.rstrip('/')}{path}"
    return path


def _payload_crafter_needed(*, families: list[str], text: str, parameters: list[str]) -> bool:
    if not parameters:
        return False
    family_set = _COMPLEX_PAYLOAD_FAMILIES.intersection(families)
    if not family_set:
        return False
    # Server-side and protocol inputs benefit from focused mutations as soon
    # as recon identifies a real parameter or message field.
    server_or_protocol = {
        "ssrf",
        "path_traversal_lfi_rfi",
        "xxe",
        "insecure_deserialization",
        "insecure_file_uploads",
        "ssti",
        "websocket_security",
        "webhook_security",
    }
    if server_or_protocol.intersection(family_set):
        return True
    if "api_abuse" in family_set:
        return bool(
            re.search(r"(?:api|json|graphql|websocket|webhook|body|header)", text, re.I)
        )
    if {"sql_injection", "nosql_injection", "ssti"}.intersection(family_set):
        return bool(
            re.search(
                r"(?:api|json|xml|form|auth|login|parser|input|param|query|body|reflect)",
                text,
                re.I,
            )
        )
    if {"xss", "dom_xss"}.intersection(family_set):
        return bool(
            re.search(
                r"(?:html|dom|script|render|search|feedback|browser|sink|reflect)",
                text,
                re.I,
            )
        )
    return False


def build_surface_coverage_plan(surface_map: dict[str, Any]) -> list[dict[str, Any]]:
    """Build concrete, target-agnostic coverage items from recon inventory.

    This function only creates ledger entries. It never sends traffic and never
    infers a vulnerability. The root agent supplies the structured inventory
    produced by recon, making the planner reusable for any web application.
    """
    surface_map = _expand_surface_map(surface_map)
    base_url = _clean(surface_map.get("base_url") or surface_map.get("target"))
    records = _endpoint_records(surface_map)
    if not records:
        records = [{"path": "/", "_source": "fallback"}]

    plan: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_item(
        *,
        title: str,
        category: str,
        surface: str,
        families: list[str],
        lane: str,
        record: dict[str, Any] | None = None,
        parameters: list[str] | None = None,
        requires_payload_crafter: bool = False,
    ) -> None:
        families = list(
            dict.fromkeys(_clean(value).casefold() for value in families if _clean(value))
        )
        if not families:
            return
        surface_text = _clean(surface)
        if parameters:
            surface_text = f"{surface_text} [parameters: {', '.join(parameters[:12])}]"
        item: dict[str, Any] = {
            "title": _clean(title),
            "category": _clean(category).casefold(),
            "surface": surface_text,
            "test_families": families,
            "priority": "required",
            "status": "planned",
            "discovery_lane": lane,
            "coverage_kind": "surface",
            "planner_source": "recon_surface_map_v1",
            "requires_payload_crafter": requires_payload_crafter,
        }
        if record:
            item["surface_kind"] = _first(record, "kind", "type", "_source")
            item["route"] = _first(
                record, "path", "url", "endpoint", "route", "action", "location"
            )
            item["method"] = (_first(record, "method", "http_method") or "GET").upper()
            item["auth_context"] = _first(record, "auth_context", "authentication", "auth")
            item["technologies"] = _clean_list(
                record.get("technologies") or record.get("technology")
            )
        if parameters:
            item["parameter"] = ", ".join(parameters[:12])
        coverage_id = stable_coverage_id(
            title=str(item["title"]), surface=str(item["surface"]), category=str(item["category"])
        )
        if coverage_id in seen:
            return
        seen.add(coverage_id)
        plan.append(item)

    for record in records:
        path = _surface_path(record, base_url)
        method = (_first(record, "method", "http_method") or "GET").upper()
        parameters = _record_parameters(record)
        text = _record_text(record)
        lower = text.casefold()
        kind = (_first(record, "kind", "type", "_source") or "").casefold()
        route = _first(record, "path", "url", "endpoint", "route", "action", "location") or "/"
        auth_signal = bool(
            re.search(
                r"(?:login|signin|logout|register|signup|auth|oauth|token|session|"
                r"password|mfa|sso)",
                lower,
            )
        )
        api_signal = (
            kind in {"api", "api_route", "json", "graphql", "websocket"}
            or route.casefold().startswith(("/api", "/graphql"))
            or "application/json" in lower
        )
        authorization_signal = bool(
            re.search(
                r"(?:account|user|admin|role|tenant|object|order|transfer|payment|id=|uuid|owner)",
                lower,
            )
        )
        state_signal = method in {"POST", "PUT", "PATCH", "DELETE"} or bool(
            re.search(
                r"(?:transfer|update|delete|create|upload|feedback|change|reset|pay|"
                r"checkout|admin|settings|logout)",
                lower,
            )
        )
        server_signal = bool(
            re.search(
                r"(?:url|uri|link|fetch|proxy|callback|webhook|redirect|file|path|"
                r"content|template|include|upload|import|preview|xml|deserialize|cfile)",
                lower,
            )
        )
        client_signal = bool(
            parameters
            or kind in {"form", "html", "js", "browser"}
            or re.search(r"(?:dom|html|script|render|search|feedback|disclaimer)", lower)
        )
        families_for_input = ["sql_injection", "xss", "nosql_injection"]

        if auth_signal:
            add_item(
                title=f"{method} {route} — authentication and session controls",
                category="authentication",
                surface=f"{path} [auth/session surface]",
                families=["authentication", "session", "auth_bypass", "token_handling"],
                lane="authentication",
                record=record,
                parameters=parameters,
                requires_payload_crafter=_payload_crafter_needed(
                    families=["sql_injection", "xss"], text=text, parameters=parameters
                ),
            )
        if authorization_signal:
            add_item(
                title=f"{method} {route} — object and function authorization",
                category="authorization",
                surface=f"{path} [object/role boundary]",
                families=["idor", "broken_function_level_authorization", "privilege_escalation"],
                lane="authorization",
                record=record,
                parameters=parameters,
            )
        if parameters or method in {"POST", "PUT", "PATCH"} or kind in {"form", "input"}:
            add_item(
                title=f"{method} {route} — input and injection handling",
                category="input_validation",
                surface=f"{path} [input surface]",
                families=families_for_input + (["ssti"] if "template" in lower else []),
                lane="injection",
                record=record,
                parameters=parameters,
                requires_payload_crafter=_payload_crafter_needed(
                    families=families_for_input, text=text, parameters=parameters
                ),
            )
        if state_signal:
            add_item(
                title=f"{method} {route} — state-changing workflow controls",
                category="business_logic",
                surface=f"{path} [state-changing workflow]",
                families=["business_logic", "csrf", "api_abuse"],
                lane="state_change",
                record=record,
                parameters=parameters,
            )
        if api_signal:
            protocol_families = ["api_mapping", "api_abuse"]
            if "graphql" in lower:
                protocol_families.append("graphql")
            if "websocket" in lower or "socket" in lower:
                protocol_families.append("websocket_security")
            if "webhook" in lower or "callback" in lower:
                protocol_families.append("webhook_security")
            add_item(
                title=f"{method} {route} — API and protocol abuse controls",
                category="api_surface",
                surface=f"{path} [API/protocol surface]",
                families=protocol_families,
                lane="api",
                record=record,
                parameters=parameters,
                requires_payload_crafter=_payload_crafter_needed(
                    families=protocol_families, text=text, parameters=parameters
                ),
            )
        if server_signal:
            server_families = ["ssrf", "path_traversal_lfi_rfi"]
            if "xml" in lower:
                server_families.append("xxe")
            if "deserialize" in lower or "serialized" in lower:
                server_families.append("insecure_deserialization")
            if "upload" in lower:
                server_families.append("insecure_file_uploads")
            if "template" in lower:
                server_families.append("ssti")
            add_item(
                title=f"{method} {route} — server-side fetch, file and parser controls",
                category="server_side",
                surface=f"{path} [server-side/file/parser surface]",
                families=server_families,
                lane="server_side",
                record=record,
                parameters=parameters,
                requires_payload_crafter=_payload_crafter_needed(
                    families=server_families, text=text, parameters=parameters
                ),
            )
        if client_signal:
            add_item(
                title=f"{method} {route} — client-side and browser sinks",
                category="client_side",
                surface=f"{path} [client/browser sink]",
                families=["xss", "dom_xss", "browser_security", "prototype_pollution"],
                lane="client_side",
                record=record,
                parameters=parameters,
                requires_payload_crafter=_payload_crafter_needed(
                    families=["xss", "dom_xss"], text=text, parameters=parameters
                ),
            )

    observations = " ".join(_clean_list(surface_map.get("observations")))
    if observations and _ERROR_MARKERS.search(observations):
        add_item(
            title="Observed error responses and information disclosure",
            category="information_disclosure",
            surface=f"{base_url or 'in-scope application'} [observed error paths]",
            families=["information_disclosure", "error_handling", "debug_exposure"],
            lane="error_disclosure",
            requires_payload_crafter=False,
        )
    technologies = _clean_list(surface_map.get("technologies") or surface_map.get("technology"))
    if technologies:
        add_item(
            title="Discovered technology and configuration surfaces",
            category="technology",
            surface=(
                f"{base_url or 'in-scope application'} "
                f"[technology: {', '.join(technologies[:8])}]"
            ),
            families=["technology_detection", "configuration", "api_spec_testing"],
            lane="technology",
            requires_payload_crafter=False,
        )
    return plan


def discovery_lane_quality_errors(
    items: list[dict[str, Any]],
    metadata: dict[str, dict[str, Any]] | None = None,
    statuses: dict[str, Any] | None = None,
) -> list[str]:
    """Check that every required lane has a matching assigned child."""
    metadata = metadata or {}
    statuses = statuses or {}
    errors: list[str] = []
    for lane, spec in DISCOVERY_LANE_SPECS.items():
        lane_items = [
            item
            for item in items
            if str(item.get("discovery_lane") or "").casefold() == lane
            and str(item.get("priority") or "required").casefold() == "required"
        ]
        if not lane_items:
            continue
        assigned_ids = {
            str(item.get("coverage_id"))
            for item in lane_items
            if item.get("coverage_id") and item.get("assigned_agent_id")
        }
        matching = False
        for agent_id, agent_metadata in metadata.items():
            if (
                not isinstance(agent_metadata, dict)
                or statuses.get(agent_id) in {"failed", "crashed", "stopped"}
            ):
                continue
            agent_ids = {str(value) for value in agent_metadata.get("coverage_ids") or []}
            task_text = " ".join(
                [
                    _clean(agent_metadata.get("task")),
                    _clean(agent_metadata.get("name")),
                    " ".join(_clean_list(agent_metadata.get("skills"))),
                ]
            ).casefold()
            lane_markers = [
                lane,
                *[str(value).casefold() for value in spec.get("families", [])],
            ]
            if assigned_ids.intersection(agent_ids) and any(
                marker in task_text for marker in lane_markers
            ):
                matching = True
                break
        if not matching:
            errors.append(
                f"Required discovery lane '{lane}' has no matching assigned child. "
                f"Use dispatch_required_discovery for {spec.get('name', lane)}."
            )
    return errors


def payload_crafter_quality_errors(
    items: list[dict[str, Any]],
    metadata: dict[str, dict[str, Any]] | None = None,
    statuses: dict[str, Any] | None = None,
) -> list[str]:
    """Ensure concrete complex surfaces receive a focused payload handoff."""
    metadata = metadata or {}
    statuses = statuses or {}
    payload_agents = [
        (agent_id, agent_metadata)
        for agent_id, agent_metadata in metadata.items()
        if isinstance(agent_metadata, dict)
        and agent_metadata.get("agent_type") == "payload_crafter"
        and statuses.get(agent_id) not in {"failed", "crashed", "stopped"}
    ]
    errors: list[str] = []
    for item in items:
        if not item.get("requires_payload_crafter"):
            continue
        coverage_id = str(item.get("coverage_id") or "")
        if any(
            coverage_id in {str(value) for value in meta.get("coverage_ids") or []}
            for _, meta in payload_agents
        ):
            continue
        errors.append(
            f"Concrete payload-capable surface {coverage_id or '<unknown>'} has no "
            "payload_crafter handoff. Dispatch it before validation/reporting."
        )
    return errors


def coverage_quality_errors(items: list[dict[str, Any]] | None = None) -> list[str]:
    """Return blocking gaps without requiring an exact vulnerability count."""
    if not items:
        return [
            "Coverage ledger is empty. Record the discovered attack-surface test "
            "obligations before finishing the scan."
        ]

    errors: list[str] = []
    unresolved = [
        item
        for item in items
        if str(item.get("priority", "required")).casefold() == "required"
        and str(item.get("status", "planned")).casefold() not in COVERAGE_TERMINAL_STATUSES
    ]
    if unresolved:
        preview = ", ".join(
            f"{item.get('coverage_id', 'unknown')} ({item.get('title', 'untitled')})"
            for item in unresolved[:8]
        )
        suffix = " ..." if len(unresolved) > 8 else ""
        errors.append(
            "Required coverage items are unresolved: "
            f"{preview}{suffix}. Finish, rule out, block with a reason, or explicitly "
            "mark the item not_tested before completing the scan."
        )
    missing_disposition = [
        item
        for item in items
        if str(item.get("status", "planned")).casefold() in COVERAGE_TERMINAL_STATUSES
        and not (_clean(item.get("evidence")) or _clean(item.get("notes")))
    ]
    if missing_disposition:
        preview = ", ".join(
            str(item.get("coverage_id", "unknown")) for item in missing_disposition[:8]
        )
        errors.append(
            "Terminal coverage items require evidence or a reason: "
            f"{preview}. Do not mark coverage complete without documenting the result."
        )
    return errors


def baseline_coverage_items(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a target-agnostic baseline with explicit discovery lanes."""
    baselines: dict[str, list[tuple[str, str, list[str], str]]] = {
        "web_application": [
            ("Surface mapping", "reconnaissance", ["recon"], "required"),
            (
                "Authentication and session controls",
                "authentication",
                ["authentication", "session"],
                "required",
            ),
            (
                "Authorization and object access",
                "authorization",
                ["idor", "broken_function_level_authorization"],
                "required",
            ),
            (
                "Input handling and injection",
                "input_validation",
                ["xss", "sql_injection"],
                "required",
            ),
            ("State-changing workflows", "business_logic", ["business_logic", "csrf"], "required"),
            (
                "API routes and abuse controls",
                "api_surface",
                ["api_mapping", "api_abuse"],
                "required",
            ),
            (
                "Server-side integrations and file access",
                "server_side",
                ["ssrf", "path_traversal_lfi_rfi"],
                "required",
            ),
            (
                "Client-side and browser sinks",
                "client_side",
                ["xss", "browser_security"],
                "required",
            ),
            (
                "Error handling and information disclosure",
                "information_disclosure",
                ["information_disclosure", "error_handling"],
                "required",
            ),
            ("Technology-specific surfaces", "technology", ["technology_detection"], "recommended"),
        ],
        "api_spec": [
            ("API surface and schema mapping", "reconnaissance", ["api_mapping"], "required"),
            (
                "API authentication and authorization",
                "authorization",
                ["authentication", "idor", "broken_function_level_authorization"],
                "required",
            ),
            (
                "API input validation",
                "input_validation",
                ["sql_injection", "xss", "api_abuse"],
                "required",
            ),
            (
                "API workflows and abuse controls",
                "business_logic",
                ["business_logic", "api_abuse"],
                "required",
            ),
        ],
        "repository": [
            (
                "Source and dependency security mapping",
                "source_review",
                ["source_aware_sast", "dependency_cve_scanning"],
                "required",
            ),
            (
                "Authentication and authorization code paths",
                "authorization",
                ["source_aware_sast"],
                "required",
            ),
            (
                "Input, output, and dangerous-sink review",
                "input_validation",
                ["source_aware_sast"],
                "required",
            ),
        ],
        "local_code": [
            ("Local source security mapping", "source_review", ["source_aware_sast"], "required"),
            (
                "Authentication and authorization code paths",
                "authorization",
                ["source_aware_sast"],
                "required",
            ),
            (
                "Input, output, and dangerous-sink review",
                "input_validation",
                ["source_aware_sast"],
                "required",
            ),
        ],
    }
    lane_by_category = {
        "reconnaissance": "reconnaissance",
        "authentication": "authentication",
        "authorization": "authorization",
        "input_validation": "injection",
        "business_logic": "state_change",
        "api_surface": "api",
        "server_side": "server_side",
        "client_side": "client_side",
        "information_disclosure": "error_disclosure",
        "technology": "technology",
        "source_review": "source_review",
    }
    result: list[dict[str, Any]] = []
    for target in targets:
        if not isinstance(target, dict):
            continue
        target_type = _clean(target.get("type")) or "unknown"
        target_label = _clean(target.get("original")) or target_type
        for title, category, test_families, priority in baselines.get(
            target_type,
            [("Target surface mapping", "reconnaissance", ["recon"], "required")],
        ):
            result.append(
                {
                    "title": title,
                    "category": category,
                    "surface": target_label,
                    "test_families": test_families,
                    "priority": priority,
                    "status": "planned",
                    "discovery_lane": lane_by_category.get(category, category),
                    "coverage_kind": "baseline",
                }
            )
    return result
