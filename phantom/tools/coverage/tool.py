"""Tools for planning and accounting for assessment coverage."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool

from phantom.core.agents import coordinator_from_context
from phantom.report.coverage import (
    DISCOVERY_LANE_SPECS,
    _PAYLOAD_CONTEXT_SKILLS,
    build_surface_coverage_plan,
    validate_agent_assignment,
)
from phantom.report.state import get_global_report_state
from phantom.skills import validate_requested_skills


logger = logging.getLogger(__name__)


def _ctx(ctx: RunContextWrapper[Any]) -> dict[str, Any]:
    return ctx.context if isinstance(ctx.context, dict) else {}


@function_tool(timeout=30)
async def list_coverage(ctx: RunContextWrapper[Any]) -> str:
    """List the current attack-surface coverage ledger.

    Use this before spawning agents and before finishing a scan. The ledger is
    Phantom's source of truth for planned, confirmed, ruled-out, blocked, and
    not-tested coverage obligations.
    """
    del ctx
    report_state = get_global_report_state()
    if report_state is None:
        return json.dumps({"success": False, "error": "Coverage state is unavailable"})
    items = await asyncio.to_thread(report_state.list_coverage_items)
    return json.dumps(
        {"success": True, "count": len(items), "items": items},
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30, strict_mode=False)
async def record_coverage(
    ctx: RunContextWrapper[Any],
    items: list[dict[str, Any]],
) -> str:
    """Create or update attack-surface coverage obligations.

    Each item requires ``title``, ``category``, ``surface``, and a non-empty
    ``test_families`` array. New items normally start as ``planned``. Agents
    update their assigned item to ``running``, ``confirmed``, ``ruled_out``,
    ``blocked``, or ``not_tested`` with evidence or a reason.
    """
    inner = _ctx(ctx)
    agent_id = str(inner.get("agent_id") or "") or None
    parent_id = inner.get("parent_id")
    report_state = get_global_report_state()
    if report_state is None:
        return json.dumps({"success": False, "error": "Coverage state is unavailable"})
    if not isinstance(items, list) or not items:
        return json.dumps({"success": False, "error": "items must be a non-empty array"})
    if len(items) > 30:
        return json.dumps({"success": False, "error": "Record at most 30 coverage items per call"})

    existing = {item.get("coverage_id"): item for item in report_state.list_coverage_items()}
    coordinator = coordinator_from_context(inner)
    current_agent_type = None
    if coordinator is not None and agent_id:
        metadata = getattr(coordinator, "metadata", {})
        if isinstance(metadata, dict) and isinstance(metadata.get(agent_id), dict):
            current_agent_type = metadata[agent_id].get("agent_type")
    prepared: list[dict[str, Any]] = []
    try:
        for raw in items:
            if not isinstance(raw, dict):
                raise ValueError("each coverage item must be an object")
            coverage_id = str(raw.get("coverage_id") or "").strip()
            current = existing.get(coverage_id) if coverage_id else None
            if current and parent_id is not None:
                owner = str(current.get("assigned_agent_id") or "")
                payload_owner = str(current.get("payload_crafter_agent_id") or "")
                permitted = owner == agent_id or (
                    current_agent_type == "payload_crafter" and payload_owner == agent_id
                )
                if owner and not permitted:
                    raise ValueError(
                        f"coverage item {coverage_id} is assigned to another agent "
                        "and cannot be updated"
                    )
            prepared.append({**current, **raw} if current else raw)
    except ValueError as exc:
        return json.dumps({"success": False, "error": str(exc)})

    written: list[dict[str, Any]] = []
    errors: list[str] = []
    for raw in prepared:
        try:
            written.append(
                await asyncio.to_thread(
                    report_state.upsert_coverage_item,
                    raw,
                    agent_id=agent_id,
                )
            )
        except (TypeError, ValueError) as exc:
            errors.append(str(exc))
    return json.dumps(
        {
            "success": not errors,
            "recorded": written,
            "errors": errors,
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=60, strict_mode=False)
async def plan_surface_coverage(
    ctx: RunContextWrapper[Any],
    surface_map: dict[str, Any],
) -> str:
    """Expand recon output into concrete, auditable coverage obligations.

    The root agent calls this once after reconnaissance. ``surface_map`` is a
    structured inventory, not a request to send traffic: include discovered
    endpoints/routes/forms, methods, parameters, auth context, technologies,
    and notable observations. The planner only writes ledger entries; it does
    not create findings and does not run payloads.
    """
    inner = _ctx(ctx)
    if inner.get("parent_id") is not None:
        return json.dumps(
            {"success": False, "error": "Only the root agent may plan scan coverage"},
            ensure_ascii=False,
        )
    report_state = get_global_report_state()
    if report_state is None:
        return json.dumps({"success": False, "error": "Coverage state is unavailable"})
    if not isinstance(surface_map, dict):
        return json.dumps({"success": False, "error": "surface_map must be an object"})

    try:
        plan = build_surface_coverage_plan(surface_map)
    except (TypeError, ValueError) as exc:
        return json.dumps({"success": False, "error": f"Invalid surface map: {exc!s}"})

    written: list[dict[str, Any]] = []
    errors: list[str] = []
    for item in plan:
        try:
            written.append(await asyncio.to_thread(report_state.upsert_coverage_item, item))
        except (TypeError, ValueError) as exc:
            errors.append(str(exc))
    if not errors:
        await asyncio.to_thread(report_state.mark_coverage_planner_used)
    return json.dumps(
        {
            "success": not errors,
            "planner": "recon_surface_map_v1",
            "planned": len(written),
            "items": written,
            "errors": errors,
        },
        ensure_ascii=False,
        default=str,
    )


def _agent_matches_lane(
    *,
    item: dict[str, Any],
    metadata: dict[str, dict[str, Any]],
    statuses: dict[str, str],
    lane: str,
) -> bool:
    assigned_id = str(item.get("assigned_agent_id") or "")
    if not assigned_id:
        return False
    agent_metadata = metadata.get(assigned_id)
    if not isinstance(agent_metadata, dict):
        return False
    if agent_metadata.get("agent_type") is not None:
        return False
    if statuses.get(assigned_id) in {"failed", "crashed", "stopped"}:
        return False
    spec = DISCOVERY_LANE_SPECS.get(lane, {})
    task_text = " ".join(
        [
            str(agent_metadata.get("task") or ""),
            " ".join(str(value) for value in agent_metadata.get("skills") or []),
        ]
    ).casefold()
    markers = [lane, *(str(value).casefold() for value in spec.get("families") or [])]
    return any(marker and marker in task_text for marker in markers)


def _scope_line(item: dict[str, Any]) -> str:
    details = [str(item.get("surface") or "")]
    if item.get("method"):
        details.append(f"method={item['method']}")
    if item.get("parameter"):
        details.append(f"parameters={item['parameter']}")
    if item.get("auth_context"):
        details.append(f"auth={item['auth_context']}")
    return " — ".join(details)


@function_tool(timeout=180, strict_mode=False)
async def dispatch_required_discovery(ctx: RunContextWrapper[Any]) -> str:
    """Dispatch one bounded discovery owner for every required web lane.

    This is the deterministic controller step after ``plan_surface_coverage``.
    It uses the ledger's discovered surfaces and starts only missing lane
    owners. Complex concrete inputs also receive a focused ``payload_crafter``
    handoff, so the root model cannot silently omit that specialist.
    """
    inner = _ctx(ctx)
    if inner.get("parent_id") is not None:
        return json.dumps(
            {
                "success": False,
                "error": "Only the root agent may dispatch required discovery lanes",
            },
            ensure_ascii=False,
        )
    parent_id = str(inner.get("agent_id") or "")
    coordinator = coordinator_from_context(inner)
    spawner = inner.get("spawn_child_agent")
    report_state = get_global_report_state()
    if not parent_id or coordinator is None or not callable(spawner) or report_state is None:
        return json.dumps(
            {
                "success": False,
                "error": "Scan coordinator, root agent, or child spawner is unavailable",
            },
            ensure_ascii=False,
        )

    items = report_state.list_coverage_items()
    metadata = getattr(coordinator, "metadata", {})
    statuses = getattr(coordinator, "statuses", {})
    parent_history = list(ctx.turn_input) if ctx.turn_input else []
    discovery_agents: list[dict[str, Any]] = []
    payload_agents: list[dict[str, Any]] = []
    skipped: list[str] = []
    errors: list[str] = []

    for lane, spec in DISCOVERY_LANE_SPECS.items():
        lane_items = [
            item
            for item in items
            if str(item.get("discovery_lane") or "").casefold() == lane
            and str(item.get("priority") or "required").casefold() == "required"
            and str(item.get("status") or "planned").casefold()
            not in {"confirmed", "ruled_out", "blocked", "not_tested"}
        ]
        if not lane_items:
            continue
        if all(
            _agent_matches_lane(item=item, metadata=metadata, statuses=statuses, lane=lane)
            for item in lane_items
        ):
            skipped.append(lane)
            continue
        coverage_ids = [
            str(item.get("coverage_id")) for item in lane_items if item.get("coverage_id")
        ]
        scope = "\n".join(f"- { _scope_line(item) }" for item in lane_items[:40])
        task = (
            f"Run the bounded {lane} discovery lane against the following in-scope surfaces. "
            "Test each listed obligation with the assigned skills, record evidence or a "
            "reason when a family is not applicable, and report concrete candidates to the "
            "root agent for independent validation. Do not expand beyond the declared scope.\n\n"
            f"Surfaces:\n{scope}"
        )
        skills = [str(value) for value in spec.get("skills") or []]
        skill_error = validate_requested_skills(skills)
        if skill_error:
            errors.append(f"{lane}: {skill_error}")
            continue
        try:
            result = await spawner(
                parent_ctx=inner,
                name=str(spec.get("name") or f"{lane} discovery"),
                task=task,
                skills=skills,
                parent_history=parent_history,
                agent_type=None,
                coverage_ids=coverage_ids,
            )
            discovery_agents.append(result)
        except Exception as exc:
            logger.exception("dispatch_required_discovery: failed lane=%s", lane)
            errors.append(f"{lane}: child spawn failed: {exc!s}")

    # Payload crafting is deterministic for concrete parser/input contexts.
    # It is intentionally bounded to one coverage item per handoff so the
    # specialist has an exact endpoint/parameter contract.
    current_items = report_state.list_coverage_items()
    payload_metadata = getattr(coordinator, "metadata", {})
    payload_statuses = getattr(coordinator, "statuses", {})
    for item in current_items:
        if not item.get("requires_payload_crafter"):
            continue
        coverage_id = str(item.get("coverage_id") or "")
        if any(
            meta.get("agent_type") == "payload_crafter"
            and coverage_id in {str(value) for value in meta.get("coverage_ids") or []}
            and payload_statuses.get(agent_id) not in {"failed", "crashed", "stopped"}
            for agent_id, meta in payload_metadata.items()
            if isinstance(meta, dict)
        ):
            continue
        families = [str(value).casefold() for value in item.get("test_families") or []]
        context_skill = next(
            (skill for family, skill in _PAYLOAD_CONTEXT_SKILLS.items() if family in families),
            None,
        )
        skills = ["vulnerabilities/web_payload_crafting"]
        if context_skill:
            skills.append(context_skill)
        task = (
            "Prepare a bounded web payload mutation set for exactly this concrete in-scope "
            "surface. Include the baseline request context, parser/rendering assumptions, "
            "safe oracle, stop conditions, detection pairing, ATT&CK mapping, cleanup, and "
            "a validator handoff. Do not broaden the target or perform unrelated testing.\n\n"
            f"Coverage ID: {coverage_id}\n"
            f"Surface: {_scope_line(item)}\n"
            f"Test families: {', '.join(families)}"
        )
        assignment_error = validate_agent_assignment(
            agent_type="payload_crafter",
            task=task,
            coverage_ids=[coverage_id],
            existing_items=current_items,
        )
        if assignment_error:
            errors.append(f"{coverage_id}: {assignment_error}")
            continue
        try:
            result = await spawner(
                parent_ctx=inner,
                name=f"Payload Crafter — {item.get('title') or coverage_id}",
                task=task,
                skills=skills,
                parent_history=parent_history,
                agent_type="payload_crafter",
                coverage_ids=[coverage_id],
            )
            payload_agents.append(result)
            if isinstance(result, dict) and result.get("success"):
                updated = {
                    **item,
                    "payload_crafter_status": "spawned",
                    "payload_crafter_agent_id": result.get("agent_id"),
                }
                await asyncio.to_thread(report_state.upsert_coverage_item, updated)
        except Exception as exc:
            logger.exception("dispatch_required_discovery: failed payload handoff=%s", coverage_id)
            errors.append(f"{coverage_id}: payload crafter spawn failed: {exc!s}")

    return json.dumps(
        {
            "success": not errors,
            "planner_used": bool(getattr(report_state, "coverage_planner_used", False)),
            "discovery_agents": discovery_agents,
            "payload_crafter_agents": payload_agents,
            "skipped_lanes": skipped,
            "errors": errors,
        },
        ensure_ascii=False,
        default=str,
    )
