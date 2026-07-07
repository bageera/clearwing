"""Prompt-builder functions for sourcehunt hunters.

Each builder renders a specialist prompt template (from
:mod:`nightwing.sourcehunt.prompts.specialists`) into a concrete string
suitable for feeding to the hunter LLM.  The function signatures and return
values match the original inline implementations in ``hunter.py``.
"""

from __future__ import annotations

from typing import Any

from nightwing.sourcehunt.state import FileTarget, SubsystemTarget

from .specialists import (
    _DEEP_SPECIALIST_FOCUS,
    _SPECIALIST_PROMPTS,
    CAMPAIGN_HINT_TEMPLATE,
    DEEP_AGENT_PROMPT,
    DISCOVERY_PROMPT,
    ENTRY_POINT_FOCUS,
    EXPLOIT_EXTENSION,
    GENERAL_HUNTER_PROMPT,
    HUNTER_EXECUTION_RULES,
    MITIGATION_REASONING,
    POOL_ACCESS_BLOCK,
    PROPAGATION_AUDIT_PROMPT,
    SEED_CORPUS_BLOCK,
    SELF_CHECK,
    SUBSYSTEM_HUNT_PROMPT,
)


def _build_hunter_prompt(
    file_target: FileTarget,
    project_name: str,
    seeded_crash: dict | None,
    semgrep_hints: list[dict] | None,
    specialist: str = "general",
) -> str:
    """Render the specialist prompt for this file."""
    seeded_crash_block = ""
    if seeded_crash:
        report = seeded_crash.get("report", "")
        seeded_crash_block = (
            f"\nA fuzz harness produced this crash for this file BEFORE you started:\n"
            f"{report[:2000]}\n"
            f"Your job is to explain the root cause and assess exploitability.\n"
        )

    semgrep_hints_block = ""
    if semgrep_hints:
        hint_lines = []
        for h in semgrep_hints[:5]:
            hint_lines.append(f"  - line {h.get('line', '?')}: {h.get('description', '')}")
        semgrep_hints_block = (
            "\nStatic analysis hints (NOT ground truth — use as starting points):\n"
            + "\n".join(hint_lines)
            + "\n"
        )

    template = _SPECIALIST_PROMPTS.get(specialist, GENERAL_HUNTER_PROMPT)
    prompt = template.format(
        project_name=project_name,
        file_path=file_target.get("path", "unknown"),
        language=file_target.get("language", "unknown"),
        loc=file_target.get("loc", 0),
        tags=", ".join(file_target.get("tags", [])) or "none",
        seeded_crash_block=seeded_crash_block,
        semgrep_hints_block=semgrep_hints_block,
    )
    return prompt + HUNTER_EXECUTION_RULES


def _build_propagation_prompt(file_target: FileTarget) -> str:
    return PROPAGATION_AUDIT_PROMPT.format(
        file_path=file_target.get("path", "unknown"),
        language=file_target.get("language", "unknown"),
        imports_by=file_target.get("imports_by", 0),
        tags=", ".join(file_target.get("tags", [])) or "none",
    )


def _build_deep_agent_prompt(
    file_target: FileTarget,
    project_name: str,
    seeded_crash: dict | None,
    semgrep_hints: list[dict] | None,
    specialist: str = "general",
    entry_point: Any = None,
    seed_context: str | None = None,
    findings_pool: Any = None,
) -> str:
    """Render the deep agent prompt for this file."""
    seeded_crash_block = ""
    if seeded_crash:
        report = seeded_crash.get("report", "")
        seeded_crash_block = (
            f"\nA fuzz harness produced this crash BEFORE you started:\n"
            f"{report[:2000]}\n"
            f"Explain the root cause and assess exploitability.\n"
        )

    semgrep_hints_block = ""
    if semgrep_hints:
        hint_lines = []
        for h in semgrep_hints[:5]:
            hint_lines.append(f"  - line {h.get('line', '?')}: {h.get('description', '')}")
        semgrep_hints_block = (
            "\nStatic analysis hints (NOT ground truth — starting points only):\n"
            + "\n".join(hint_lines)
            + "\n"
        )

    focus = _DEEP_SPECIALIST_FOCUS.get(specialist, "")
    specialist_focus = f"\n{focus}\n" if focus else ""

    prompt = DEEP_AGENT_PROMPT.format(
        project_name=project_name,
        file_path=file_target.get("path", "unknown"),
        language=file_target.get("language", "unknown"),
        tags=", ".join(file_target.get("tags", [])) or "none",
        seeded_crash_block=seeded_crash_block,
        semgrep_hints_block=semgrep_hints_block,
        specialist_focus=specialist_focus,
    )

    if entry_point is not None:
        prompt += "\n" + ENTRY_POINT_FOCUS.format(
            entry_point=entry_point.function_name,
            file_path=file_target.get("path", "unknown"),
            start_line=entry_point.start_line,
            end_line=entry_point.end_line,
            entry_type=entry_point.entry_type,
        )
    if seed_context:
        prompt += "\n" + SEED_CORPUS_BLOCK.format(seed_context=seed_context)

    if findings_pool is not None:
        count = len(findings_pool.all_findings())
        if count > 0:
            prompt += "\n" + POOL_ACCESS_BLOCK.format(count=count)

    return prompt


def _build_unconstrained_prompt(
    file_target: FileTarget,
    project_name: str,
    seeded_crash: dict | None,
    semgrep_hints: list[dict] | None,
    campaign_hint: str | None = None,
    exploit_mode: bool = False,
    entry_point: Any = None,
    seed_context: str | None = None,
    findings_pool: Any = None,
) -> str:
    """Build the unconstrained discovery prompt for any agent mode."""
    seed_parts: list[str] = []
    if seeded_crash:
        report = seeded_crash.get("report", "")
        seed_parts.append(
            f"\nA fuzz harness produced this crash BEFORE you started:\n"
            f"{report[:2000]}\n"
            f"Explain the root cause and assess exploitability.\n"
        )
    if semgrep_hints:
        hint_lines = []
        for h in semgrep_hints[:5]:
            hint_lines.append(f"  - line {h.get('line', '?')}: {h.get('description', '')}")
        seed_parts.append(
            "\nStatic analysis hints (NOT ground truth — starting points only):\n"
            + "\n".join(hint_lines)
            + "\n"
        )
    seed_context_block = "".join(seed_parts)

    prompt = DISCOVERY_PROMPT.format(
        file_path=file_target.get("path", "unknown"),
        project_name=project_name,
        seed_context_block=seed_context_block,
    )

    if exploit_mode:
        prompt += "\n" + EXPLOIT_EXTENSION
        prompt += "\n" + MITIGATION_REASONING

    if campaign_hint:
        prompt += "\n" + CAMPAIGN_HINT_TEMPLATE.format(objective=campaign_hint)

    if entry_point is not None:
        prompt += "\n" + ENTRY_POINT_FOCUS.format(
            entry_point=entry_point.function_name,
            file_path=file_target.get("path", "unknown"),
            start_line=entry_point.start_line,
            end_line=entry_point.end_line,
            entry_type=entry_point.entry_type,
        )
    if seed_context:
        prompt += "\n" + SEED_CORPUS_BLOCK.format(seed_context=seed_context)

    if findings_pool is not None:
        count = len(findings_pool.all_findings())
        if count > 0:
            prompt += "\n" + POOL_ACCESS_BLOCK.format(count=count)

    prompt += "\n" + SELF_CHECK

    return prompt


def _build_subsystem_prompt(
    subsystem: SubsystemTarget,
    project_name: str,
    findings_pool: Any = None,
    callgraph: Any = None,
) -> str:
    """Build the subsystem hunt prompt listing all files and cross-file relationships."""
    file_lines = []
    subsystem_files = set()
    for ft in subsystem.files[:50]:
        path = ft.get("path", "?")
        subsystem_files.add(path)
        pri = ft.get("priority", 0.0)
        tags = ", ".join(ft.get("tags", [])) or "none"
        file_lines.append(f"  {path} (priority={pri:.1f}, tags={tags})")
    file_listing = "\n".join(file_lines)

    cross_file_calls = ""
    if callgraph is not None:
        edges: list[str] = []
        for ft in subsystem.files[:50]:
            src = ft.get("path", "")
            called = callgraph.calls_out.get(src, set())
            for func_name in called:
                for def_file in callgraph.defined_in.get(func_name, set()):
                    if def_file != src and def_file in subsystem_files:
                        edges.append(f"  {src} -> {def_file} (via {func_name})")
                        if len(edges) >= 30:
                            break
                if len(edges) >= 30:
                    break
            if len(edges) >= 30:
                break
        if edges:
            cross_file_calls = (
                "\nCross-file call edges within this subsystem:\n" + "\n".join(edges) + "\n"
            )

    existing_findings_block = ""
    if findings_pool is not None:
        pool_findings = []
        for fp in subsystem_files:
            pool_findings.extend(findings_pool.query(file_path=fp))
        if pool_findings:
            lines = [
                f"\nPer-file hunters already found {len(pool_findings)} findings in this subsystem:"
            ]
            for f in pool_findings[:10]:
                lines.append(
                    f"  - {f.get('file', '?')}:{f.get('line_number', '?')} "
                    f"({f.get('cwe', '?')}, {f.get('severity', '?')}): "
                    f"{f.get('description', '')[:150]}"
                )
            if len(pool_findings) > 10:
                lines.append(f"  ... and {len(pool_findings) - 10} more")
            lines.append(
                "Use query_findings_pool for the full list. "
                "Focus on NEW cross-file bugs, not re-discovering these.\n"
            )
            existing_findings_block = "\n".join(lines)

    entry_points_block = ""
    if subsystem.entry_points:
        ep_lines = ["\nEntry points from untrusted input:"]
        for ep in subsystem.entry_points[:20]:
            ep_lines.append(
                f"  - {getattr(ep, 'function_name', '?')} "
                f"in {getattr(ep, 'file_path', '?')} "
                f"(type: {getattr(ep, 'entry_type', '?')})"
            )
        if len(subsystem.entry_points) > 20:
            ep_lines.append(f"  ... and {len(subsystem.entry_points) - 20} more")
        entry_points_block = "\n".join(ep_lines) + "\n"

    return SUBSYSTEM_HUNT_PROMPT.format(
        subsystem_name=subsystem.name,
        project_name=project_name,
        file_count=len(subsystem.files),
        root_path=subsystem.root_path,
        file_listing=file_listing,
        cross_file_calls=cross_file_calls,
        existing_findings_block=existing_findings_block,
        entry_points_block=entry_points_block,
    )
