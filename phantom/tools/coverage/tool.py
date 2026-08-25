"""Tools for planning and accounting for assessment coverage."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from phantom.report.state import get_global_report_state


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
    prepared: list[dict[str, Any]] = []
    try:
        for raw in items:
            if not isinstance(raw, dict):
                raise ValueError("each coverage item must be an object")
            coverage_id = str(raw.get("coverage_id") or "").strip()
            current = existing.get(coverage_id) if coverage_id else None
            if current and parent_id is not None:
                owner = str(current.get("assigned_agent_id") or "")
                if owner and owner != agent_id:
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
