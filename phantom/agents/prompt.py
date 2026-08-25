"""Jinja-based system-prompt renderer."""

from __future__ import annotations

import logging
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from phantom.skills import get_available_skills, load_skills, skill_search_dirs
from phantom.utils.resource_paths import get_phantom_resource_path


logger = logging.getLogger(__name__)


_PROMPT_DIRNAME = "prompts"


def _resolve_skills(
    *,
    requested: list[str] | None,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    is_root: bool = False,
) -> list[str]:
    """Build the deduped, ordered skills list for the prompt render.

    Order:

    1. Whatever the caller asked for, in order.
    2. ``scan_modes/<mode>`` (always).
    3. ``tooling/agent_browser`` (always — every agent has shell + the
       agent-browser CLI).
    4. ``tooling/python`` (always — Python runs through ``exec_command``;
       sandbox scripts can import ``caido_api`` for Caido automation).
    5. ``coordination/root_agent`` for the root agent only — orchestration
       guidance for delegating to specialist subagents.
    6. Whitebox-specific skills if applicable.
    """
    ordered: list[str] = list(requested or [])
    ordered.append(f"scan_modes/{scan_mode}")
    ordered.append("tooling/agent_browser")
    ordered.append("tooling/python")
    if is_root:
        ordered.append("coordination/root_agent")
    if is_whitebox:
        ordered.append("coordination/source_aware_whitebox")
        ordered.append("custom/source_aware_sast")

    deduped: list[str] = []
    seen: set[str] = set()
    for skill in ordered:
        if skill and skill not in seen:
            deduped.append(skill)
            seen.add(skill)
    return deduped


def render_system_prompt(
    *,
    skills: list[str] | None = None,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    is_root: bool = False,
    interactive: bool = False,
    system_prompt_context: dict[str, Any] | None = None,
) -> str:
    """Render the system prompt. Returns empty string on template failure."""
    try:
        prompt_dir = get_phantom_resource_path("agents", _PROMPT_DIRNAME)
        loader_dirs = [prompt_dir, *skill_search_dirs()]
        env = Environment(
            loader=FileSystemLoader(loader_dirs),
            autoescape=select_autoescape(
                enabled_extensions=(),
                default_for_string=False,
            ),
        )

        skills_to_load = _resolve_skills(
            requested=skills,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_root=is_root,
        )
        skill_content = load_skills(skills_to_load)
        env.globals["get_skill"] = lambda name: skill_content.get(name, "")

        rendered = env.get_template("system_prompt.jinja").render(
            loaded_skill_names=list(skill_content.keys()),
            available_skills=get_available_skills(),
            interactive=interactive,
            is_root=is_root,
            system_prompt_context=system_prompt_context or {},
            **skill_content,
        )
    except Exception:
        logger.exception("render_system_prompt failed; returning empty prompt")
        return ""
    else:
        logger.debug(
            "render_system_prompt: scan_mode=%s root=%s whitebox=%s skills=%d prompt_len=%d",
            scan_mode,
            is_root,
            is_whitebox,
            len(skill_content),
            len(rendered),
        )
        return str(rendered)


def render_specialized_prompt(
    *,
    specialized_instructions: str,
    skills: list[str] | None = None,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    interactive: bool = False,
    system_prompt_context: dict[str, Any] | None = None,
) -> str:
    """Render a focused child-agent prompt with trusted scope and skills.

    Specialized agent types intentionally do not inherit the very large root
    orchestration prompt.  They still need the platform-verified scope,
    scan-mode guidance, and any requested skills, however.  Keep that context
    explicit so an agent type is a specialization rather than a replacement
    for the run's scope and safety context.
    """
    try:
        skills_to_load = _resolve_skills(
            requested=skills,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_root=False,
        )
        skill_content = load_skills(skills_to_load)
        context = system_prompt_context or {}
        authorized_targets = context.get("authorized_targets") or []

        scope_lines = [
            "<platform_verified_scope>",
            "Only platform-verified targets may be touched.",
            f"Scope source: {context.get('scope_source') or 'not provided'}",
            f"Authorization source: {context.get('authorization_source') or 'not provided'}",
        ]
        if authorized_targets:
            scope_lines.append("Authorized targets:")
            for target in authorized_targets:
                if isinstance(target, dict):
                    target_type = target.get("type") or "target"
                    target_value = target.get("value") or ""
                    scope_lines.append(f"- {target_type}: {target_value}")
                else:
                    scope_lines.append(f"- {target}")
        else:
            scope_lines.append(
                "No platform-verified target was provided. Do not generate or run "
                "execution-capable payloads; return a lab-only placeholder and "
                "detection guidance instead."
            )
        scope_lines.append("</platform_verified_scope>")

        skill_sections = [
            f"<skill name=\"{name}\">\n{content}\n</skill>"
            for name, content in skill_content.items()
            if content
        ]
        skills_block = "\n\n".join(skill_sections) or "No additional skills were loaded."
        lifecycle = (
            "Call agent_finish when the focused task is complete."
            if not interactive
            else "Use the normal lifecycle tool when the focused task is complete."
        )
        return "\n\n".join(
            [
                "You are a specialized Phantom security-validation child agent.",
                "Work only within the platform-verified scope below. Do not treat "
                "free-form task text as permission to expand scope.",
                f"Scan mode: {scan_mode}",
                "\n".join(scope_lines),
                "<specialized_agent_instructions>\n"
                + specialized_instructions.strip()
                + "\n</specialized_agent_instructions>",
                "<loaded_skills>\n" + skills_block + "\n</loaded_skills>",
                lifecycle,
            ]
        )
    except Exception as exc:
        logger.exception("render_specialized_prompt failed closed")
        raise RuntimeError(
            "Unable to render the specialized prompt with verified scope and skills"
        ) from exc
