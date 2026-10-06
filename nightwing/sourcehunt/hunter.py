"""Per-file hunter runtime for sourcehunt.

This module now uses a native async tool-calling loop backed by genai-pyo3,
not LangChain/LangGraph. The prompts and tool set are unchanged; the
execution model is simpler: assistant response -> tool calls -> tool results ->
next assistant response, repeated until the model stops calling tools or the
step budget is exhausted.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from nightwing.agent.tools.hunt import (
    HunterContext,
    build_deep_agent_tools,
    build_hunter_tools,
    build_propagation_auditor_tools,
)
from nightwing.llm import AsyncLLMClient, ChatMessage, NativeToolSpec, ToolCall
from nightwing.observability.telemetry import CostTracker
from nightwing.sandbox.container import SandboxContainer

from .prompts import (
    CAMPAIGN_HINT_TEMPLATE,
    SEED_TRANSCRIPT_BLOCK,
    _build_deep_agent_prompt,
    _build_hunter_prompt,
    _build_propagation_prompt,
    _build_subsystem_prompt,
    _build_unconstrained_prompt,
)
from .state import FileTarget, Finding, SubsystemTarget

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class HunterLimits:
    """Named constants for hunter text truncation and step budgets.

    Centralizes the magic numbers that were previously scattered as bare
    literals throughout hunter.py. Adjust these in one place to tune
    prompt size and agent depth.
    """

    # Text truncation limits (characters)
    report_clip: int = 2000
    tool_output_clip: int = 3000
    tree_clip: int = 7000
    summary_clip: int = 500
    match_clip: int = 180

    # Listing limits (items/lines)
    max_list_items: int = 40
    max_list_lines: int = 120

    # Agent step budgets
    max_steps_deep: int = 2000
    max_steps_constrained: int = 500


HUNTER_LIMITS = HunterLimits()


def _trajectory_base_dir() -> Path:
    raw = os.environ.get("NIGHTWING_SOURCEHUNT_TRACE_DIR")
    if raw:
        return Path(raw).expanduser()
    from nightwing.core.config import nightwing_home

    return nightwing_home() / "sourcehunt" / "trajectories"


def _sanitize_path_component(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._")
    return cleaned or "unknown"


def _trajectory_path(ctx: HunterContext) -> Path:
    if ctx.trajectory_dir is not None:
        return Path(cast(str, ctx.trajectory_dir)) / "transcript.jsonl"
    session = _sanitize_path_component(ctx.session_id or "no_session")
    rel_file = _sanitize_path_component((ctx.file_path or "unknown").replace("/", "__"))
    return _trajectory_base_dir() / session / f"{rel_file}.jsonl"


def _serialize_tool_call(tool_call: ToolCall) -> dict[str, Any]:
    if hasattr(tool_call, "to_dict"):
        return dict(tool_call.to_dict())
    return {
        "call_id": getattr(tool_call, "call_id", ""),
        "fn_name": getattr(tool_call, "fn_name", ""),
        "fn_arguments": getattr(tool_call, "fn_arguments", None),
        "fn_arguments_json": getattr(tool_call, "fn_arguments_json", ""),
    }


def _serialize_message(message: ChatMessage) -> dict[str, Any]:
    if hasattr(message, "to_dict"):
        return dict(message.to_dict())
    tool_calls = getattr(message, "tool_calls", None) or []
    return {
        "role": message.role,
        "content": message.content,
        "tool_calls": [_serialize_tool_call(tc) for tc in tool_calls],
        "tool_response_call_id": getattr(message, "tool_response_call_id", None),
    }


def _first_matching_line(path: Path, pattern: str) -> int | None:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line_number, line in enumerate(handle, start=1):
                if re.search(pattern, line):
                    return line_number
    except OSError:
        return None
    return None


def _memory_safety_heuristic_hints(
    repo_path: str,
    file_target: FileTarget,
) -> list[dict[str, Any]]:
    """Derive high-signal, file-local hints for memory-safety hunters.

    The goal is not to prove a bug statically here; it is to surface concrete
    candidate mechanisms already visible in the source tree so the hunter does
    not get stuck on generic memcpy noise.

    The pattern tables and probe logic live in
    :mod:`nightwing.sourcehunt.heuristics.memory_safety`; this thin wrapper
    preserves the public call site used by the hunter and the tests.
    """
    from nightwing.sourcehunt.heuristics.memory_safety import (
        derive_memory_safety_hints,
    )

    return derive_memory_safety_hints(repo_path, file_target)


@dataclass
class HunterTrajectoryLogger:
    path: Path

    @classmethod
    def for_hunter(
        cls,
        ctx: HunterContext,
        *,
        prompt: str,
        initial_messages: list[ChatMessage],
        tools: list[NativeToolSpec],
    ) -> HunterTrajectoryLogger:
        path = _trajectory_path(ctx)
        path.parent.mkdir(parents=True, exist_ok=True)
        logger_obj = cls(path=path)
        logger_obj.log(
            "start",
            {
                "session_id": ctx.session_id,
                "file_path": ctx.file_path,
                "specialist": ctx.specialist,
                "prompt": prompt,
                "tools": [tool.name for tool in tools],
                "seeded_crash": ctx.seeded_crash,
            },
        )
        for message in initial_messages:
            logger_obj.log(
                "message",
                {
                    "step": 0,
                    "message": _serialize_message(message),
                },
            )
        return logger_obj

    def log(self, event: str, payload: dict[str, Any]) -> None:
        record = {
            "ts": time.time(),
            "event": event,
            **payload,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")


# --- Specialist routing -----------------------------------------------------


def _choose_specialist(file_target: FileTarget) -> str:
    """Route a file to a hunter specialist based on its tags + language.

    Order matters: more specific specialists win over more general ones.
    The precedence reflects which specialist's prompt is MOST directly
    applicable — a syscall_entry file gets the kernel_syscall specialist
    even if it also has memory_unsafe tags, because the kernel-specific
    invariants dominate the analysis.

    Precedence (highest to lowest):
        1. kernel_syscall — syscall_entry tag (Linux/BSD kernel code)
        2. crypto_primitive — crypto tag + C/C++/Rust primitive implementation
        3. web_framework — Python/Node/Ruby/PHP files in web handler roles
        4. memory_safety — memory_unsafe / parser / fuzzable
        5. logic_auth — auth_boundary (or crypto in a non-primitive language)
        6. general — everything else
    """
    tags = set(file_target.get("tags", []))
    language = (file_target.get("language") or "").lower()

    # 1. Kernel / syscall: highest specificity
    if "syscall_entry" in tags:
        return "kernel_syscall"

    # 2. Crypto primitive implementations: C/C++/Rust files tagged crypto
    #    that are doing actual primitive math (AES block, SHA compression,
    #    EC point ops) deserve the primitive specialist. Protocol-level
    #    crypto bugs in Python/Node fall through to logic_auth.
    if "crypto" in tags and language in ("c", "cpp", "rust"):
        return "crypto_primitive"

    # 3. Web framework: dynamic-language files with web-framework signals.
    #    The tagger doesn't set a dedicated web_framework tag yet, so we
    #    pick up the case via language + directory hints.
    web_languages = {"python", "javascript", "typescript", "ruby", "php"}
    web_path_hints = {"views", "routes", "handlers", "controllers", "api"}
    path = (file_target.get("path") or "").lower()
    path_parts = set(path.split("/"))
    if language in web_languages and (path_parts & web_path_hints):
        return "web_framework"

    # 4. Memory safety: C/C++/unsafe code, parsers, fuzzable entry points
    if "memory_unsafe" in tags or "parser" in tags or "fuzzable" in tags:
        return "memory_safety"

    # 5. Logic / auth: auth boundaries and protocol-level crypto
    if "auth_boundary" in tags or "crypto" in tags:
        return "logic_auth"

    return "general"


def build_subsystem_hunter_agent(
    subsystem: SubsystemTarget,
    repo_path: str,
    sandbox: SandboxContainer | None,
    llm: AsyncLLMClient,
    session_id: str,
    project_name: str = "target",
    budget_usd: float = 100.0,
    findings_pool: Any = None,
    campaign_hint: str | None = None,
    callgraph: Any = None,
) -> tuple[NativeHunter, HunterContext]:
    """Build a subsystem-level hunter agent (spec 006).

    Always uses deep agent mode with a generous step budget.
    """
    ctx = HunterContext(
        repo_path=repo_path,
        sandbox=sandbox,
        findings=[],
        file_path=subsystem.root_path,
        session_id=session_id,
        specialist="subsystem",
        findings_pool=findings_pool,
    )

    tools = build_deep_agent_tools(ctx)
    prompt = _build_subsystem_prompt(
        subsystem,
        project_name,
        findings_pool=findings_pool,
        callgraph=callgraph,
    )

    if campaign_hint:
        prompt += "\n" + CAMPAIGN_HINT_TEMPLATE.format(objective=campaign_hint)

    return NativeHunter(
        llm=llm,
        prompt=prompt,
        tools=tools,
        ctx=ctx,
        max_steps=HUNTER_LIMITS.max_steps_deep,
        agent_mode="deep",
        budget_usd=budget_usd,
        initial_user_message=(
            f"Hunt for cross-file vulnerabilities in the {subsystem.name} "
            f"subsystem ({len(subsystem.files)} files under {subsystem.root_path})."
        ),
    ), ctx


# --- Public factory ----------------------------------------------------------


@dataclass
class HunterRunResult:
    findings: list[Finding]
    cost_usd: float
    tokens_used: int
    stop_reason: str  # "completed" | "budget_exhausted" | "max_steps"
    transcript_summary: str = ""


@dataclass
class NativeHunter:
    llm: AsyncLLMClient
    prompt: str
    tools: list[NativeToolSpec]
    ctx: HunterContext
    max_steps: int = 20
    agent_mode: str = "constrained"  # "constrained" | "deep"
    budget_usd: float = 0.0  # 0 = unlimited (bounded by max_steps)
    initial_user_message: str = ""  # spec 006: override default first message

    def _should_stop(self, step: int, cost_usd: float) -> str | None:
        """Return a stop reason string, or None to continue."""
        if self.budget_usd > 0 and cost_usd >= self.budget_usd * 0.9:
            return "budget_exhausted"
        if step > self.max_steps:
            return "max_steps"
        return None

    async def arun(self) -> HunterRunResult:
        user_msg = (
            self.initial_user_message
            or f"Hunt for vulnerabilities in {self.ctx.file_path or 'unknown'}."
        )
        messages: list[ChatMessage] = [ChatMessage("user", user_msg)]
        trajectory = HunterTrajectoryLogger.for_hunter(
            self.ctx,
            prompt=self.prompt,
            initial_messages=messages,
            tools=self.tools,
        )
        total_input_tokens = 0
        total_output_tokens = 0
        total_cost_usd = 0.0
        repeated_tool_calls: dict[tuple[str, str], int] = {}
        tools_by_name = {tool.name: tool for tool in self.tools}
        throttle_repeats = self.agent_mode == "constrained"
        last_assistant_text = ""

        step = 0
        while True:
            step += 1
            stop_reason = self._should_stop(step, total_cost_usd)
            if stop_reason:
                logger.warning(
                    "Hunter stopped for %s: %s (step=%d, cost=$%.4f, findings=%d)",
                    self.ctx.file_path,
                    stop_reason,
                    step - 1,
                    total_cost_usd,
                    len(self.ctx.findings),
                )
                trajectory.log(
                    "finish",
                    {
                        "step": step - 1,
                        "status": stop_reason,
                        "findings": [self._serialize_finding(f) for f in self.ctx.findings],
                        "total_input_tokens": total_input_tokens,
                        "total_output_tokens": total_output_tokens,
                        "total_cost_usd": total_cost_usd,
                    },
                )
                return HunterRunResult(
                    findings=list(self.ctx.findings),
                    cost_usd=total_cost_usd,
                    tokens_used=total_input_tokens + total_output_tokens,
                    stop_reason=stop_reason,
                    transcript_summary=last_assistant_text[-HUNTER_LIMITS.summary_clip :],
                )

            response = await self.llm.achat(
                messages=messages,
                system=self.prompt,
                tools=self.tools,
            )
            # Preserve the provider's reasoning_content alongside the
            # visible text. `response.first_text()` only returns the
            # first Text part — reasoning/thinking blocks are separate
            # and used to be dropped, which silently hid the most useful
            # part of the trace for reasoning models (GPT-5.x, o-series,
            # Claude thinking). The hunter's old `think()` scratchpad
            # tool tried to compensate; native reasoning obsoletes it.
            trajectory.log(
                "message",
                {
                    "step": step,
                    "message": _serialize_message(
                        ChatMessage(
                            "assistant",
                            response.first_text() or "",
                            tool_calls=response.tool_calls(),
                        )
                    ),
                    "reasoning_content": response.reasoning_content,
                    "usage": {
                        "input_tokens": response.usage.prompt_tokens or 0,
                        "output_tokens": response.usage.completion_tokens or 0,
                        "total_tokens": response.usage.total_tokens or 0,
                    },
                    "model": response.provider_model_name,
                },
            )
            total_input_tokens += response.usage.prompt_tokens or 0
            total_output_tokens += response.usage.completion_tokens or 0
            total_cost_usd += _estimate_cost_usd(
                response.usage.prompt_tokens or 0,
                response.usage.completion_tokens or 0,
                self.llm.model_name,
            )

            last_assistant_text = response.first_text() or ""
            tool_calls_in_response = response.tool_calls()
            if tool_calls_in_response:
                messages.append(
                    ChatMessage(
                        "assistant",
                        response.first_text() or "",
                        tool_calls=tool_calls_in_response,
                    )
                )
                for tool_call in tool_calls_in_response:
                    tool_arguments = tool_call.fn_arguments
                    if not isinstance(tool_arguments, dict):
                        tool_arguments = {}

                    skipped = False
                    if throttle_repeats:
                        key = (tool_call.fn_name, tool_call.fn_arguments_json)
                        repeated_tool_calls[key] = repeated_tool_calls.get(key, 0) + 1
                        if repeated_tool_calls[key] > 3:
                            skipped = True

                    if skipped:
                        tool_output = {
                            "error": (
                                "tool call skipped because the assistant repeated the same "
                                "call too many times"
                            )
                        }
                        tool_summary = _tool_output_text(
                            tool_call.fn_name,
                            tool_arguments,
                            tool_output,
                        )
                        trajectory.log(
                            "tool_result",
                            {
                                "step": step,
                                "tool_call": _serialize_tool_call(tool_call),
                                "tool_output": tool_output,
                                "tool_summary": tool_summary,
                                "repeated_skip": True,
                            },
                        )
                    else:
                        trajectory.log(
                            "tool_call",
                            {
                                "step": step,
                                "tool_call": _serialize_tool_call(tool_call),
                            },
                        )
                        tool_output = await self._run_tool(tools_by_name, tool_call)
                        tool_summary = _tool_output_text(
                            tool_call.fn_name,
                            tool_arguments,
                            tool_output,
                        )
                        trajectory.log(
                            "tool_result",
                            {
                                "step": step,
                                "tool_call": _serialize_tool_call(tool_call),
                                "tool_output": tool_output,
                                "tool_summary": tool_summary,
                                "repeated_skip": False,
                            },
                        )
                    messages.append(
                        ChatMessage(
                            "tool",
                            tool_summary,
                            tool_response_call_id=tool_call.call_id,
                        )
                    )
                    trajectory.log(
                        "message",
                        {
                            "step": step,
                            "message": _serialize_message(messages[-1]),
                        },
                    )
                continue

            if last_assistant_text:
                messages.append(ChatMessage("assistant", last_assistant_text))
            logger.info(
                "Hunter finished for %s after %d steps findings=%d",
                self.ctx.file_path,
                step,
                len(self.ctx.findings),
            )
            trajectory.log(
                "finish",
                {
                    "step": step,
                    "status": "completed",
                    "findings": [self._serialize_finding(f) for f in self.ctx.findings],
                    "total_input_tokens": total_input_tokens,
                    "total_output_tokens": total_output_tokens,
                    "total_cost_usd": total_cost_usd,
                },
            )
            return HunterRunResult(
                findings=list(self.ctx.findings),
                cost_usd=total_cost_usd,
                tokens_used=total_input_tokens + total_output_tokens,
                stop_reason="completed",
                transcript_summary=last_assistant_text[-HUNTER_LIMITS.summary_clip :],
            )

    async def _run_tool(
        self,
        tools_by_name: dict[str, NativeToolSpec],
        tool_call: ToolCall,
    ) -> Any:
        tool = tools_by_name.get(tool_call.fn_name)
        if tool is None:
            return {"error": f"unknown tool: {tool_call.fn_name}"}
        started = time.monotonic()
        try:
            arguments = tool_call.fn_arguments
            if not isinstance(arguments, dict):
                arguments = {}
            return await tool.ainvoke(arguments)
        except Exception as exc:
            logger.warning(
                "Hunter tool %s failed for %s: %s",
                tool_call.fn_name,
                self.ctx.file_path,
                exc,
            )
            return {"error": f"{type(exc).__name__}: {exc}"}
        finally:
            duration_ms = int((time.monotonic() - started) * 1000)
            try:
                CostTracker().record_tool_call(tool_call.fn_name, duration_ms)
            except Exception:
                logger.debug("Tool usage recording failed", exc_info=True)

    @staticmethod
    def _serialize_finding(finding: Finding) -> dict[str, Any]:
        return {
            "id": finding.get("id"),
            "file": finding.get("file"),
            "line_number": finding.get("line_number"),
            "severity": finding.get("severity"),
            "cwe": finding.get("cwe"),
            "description": finding.get("description"),
            "evidence_level": finding.get("evidence_level"),
        }


def _clip_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    clipped = text[:limit].rstrip()
    return f"{clipped}\n... truncated {len(text) - len(clipped)} chars ..."


def _summarize_match_list(tool_name: str, value: list[Any]) -> str:
    if not value:
        return f"{tool_name}: no matches."
    errors = [item.get("error") for item in value if isinstance(item, dict) and item.get("error")]
    if errors:
        return f"{tool_name}: error: {errors[0]}"

    rendered: list[str] = []
    for item in value[:12]:
        if isinstance(item, dict):
            file = item.get("file", "?")
            line_number = item.get("line_number", "?")
            matched_text = str(item.get("matched_text", "")).strip()
            rendered.append(
                f"- {file}:{line_number}: {_clip_text(matched_text, HUNTER_LIMITS.match_clip)}"
            )
        else:
            rendered.append(f"- {_clip_text(str(item), HUNTER_LIMITS.match_clip)}")

    omitted = len(value) - len(rendered)
    header = f"{tool_name}: {len(value)} matches"
    if omitted > 0:
        header += f" ({omitted} omitted)"
    return "\n".join([header, *rendered])


def _summarize_tree_listing(arguments: dict[str, Any], value: list[Any]) -> str:
    dir_path = str(arguments.get("dir_path", "."))
    if not value:
        return f"list_source_tree({dir_path}): empty."
    rendered = [
        f"- {_clip_text(str(item), HUNTER_LIMITS.match_clip)}"
        for item in value[: HUNTER_LIMITS.max_list_items]
    ]
    omitted = len(value) - len(rendered)
    header = f"list_source_tree({dir_path}): {len(value)} entries"
    if omitted > 0:
        header += f" ({omitted} omitted; narrow dir_path or max_depth if you need more)"
    return "\n".join([header, *rendered])


def _summarize_read_source(arguments: dict[str, Any], value: str) -> str:
    path = str(arguments.get("path", "unknown"))
    start_line = int(arguments.get("start_line", 1) or 1)
    end_line = arguments.get("end_line", -1)
    header = f"read_source_file({path}, start_line={start_line}, end_line={end_line}):"
    lines = value.splitlines()
    if len(lines) > HUNTER_LIMITS.max_list_lines:
        kept_lines = lines[: HUNTER_LIMITS.max_list_lines]
        body = "\n".join(kept_lines)
        body += f"\n... truncated {len(lines) - len(kept_lines)} lines; request a narrower range if needed ..."
        return f"{header}\n{_clip_text(body, HUNTER_LIMITS.tree_clip)}"
    return f"{header}\n{_clip_text(value, HUNTER_LIMITS.tree_clip)}"


def _tool_output_text(tool_name: str, arguments: dict[str, Any], value: Any) -> str:
    if isinstance(value, str):
        if tool_name == "read_source_file":
            return _summarize_read_source(arguments, value)
        return _clip_text(value, HUNTER_LIMITS.tool_output_clip)
    if isinstance(value, list):
        if tool_name in {"grep_source", "find_callers"}:
            return _summarize_match_list(tool_name, value)
        if tool_name == "list_source_tree":
            return _summarize_tree_listing(arguments, value)
        try:
            return _clip_text(
                json.dumps(value, indent=2, sort_keys=True), HUNTER_LIMITS.tool_output_clip
            )
        except Exception:
            return _clip_text(str(value), HUNTER_LIMITS.tool_output_clip)
    try:
        return _clip_text(
            json.dumps(value, indent=2, sort_keys=True), HUNTER_LIMITS.tool_output_clip
        )
    except Exception:
        return _clip_text(str(value), HUNTER_LIMITS.tool_output_clip)


def _estimate_cost_usd(input_tokens: int, output_tokens: int, model: str) -> float:
    pricing = CostTracker.PRICING.get(model, CostTracker.PRICING[CostTracker._DEFAULT_MODEL])
    return (input_tokens * pricing["input"] + output_tokens * pricing["output"]) / 1_000_000


def build_hunter_agent(
    file_target: FileTarget,
    repo_path: str,
    sandbox: SandboxContainer | None,
    llm: AsyncLLMClient,
    session_id: str,
    project_name: str = "target",
    specialist: str | None = None,
    seeded_crash: dict | None = None,
    semgrep_hints: list[dict] | None = None,
    variant_seed: dict | None = None,
    sandbox_manager: Any = None,  # v0.4: HunterSandbox manager for variants
    default_sanitizers: tuple = ("asan", "ubsan"),  # v0.4: primary sanitizer combo
    agent_mode: str = "constrained",  # "constrained" | "deep"
    budget_usd: float = 0.0,
    prompt_mode: str = "unconstrained",  # "unconstrained" | "specialist"
    campaign_hint: str | None = None,
    exploit_mode: bool = False,
    seed_transcript: str | None = None,
    entry_point: Any = None,
    seed_context: str | None = None,
    findings_pool: Any = None,
) -> tuple[NativeHunter, HunterContext]:
    """Build a per-file native hunter runtime.

    Args:
        file_target: The FileTarget to scope the hunter to.
        repo_path: Absolute host path to the cloned repo.
        sandbox: SandboxContainer for compile/run tools. May be None for tests
                 (the tools fall back to host file I/O for read/grep, and
                 return errors for compile/run).
        llm: Native async LLM client.
        session_id: Audit session id.
        project_name: Project name for the prompt header.
        specialist: Override the auto-selected specialist. v0.1 always uses
                    "general" except when tier=="C" → "propagation".
        seeded_crash: v0.2 — crash evidence from the harness generator.
        semgrep_hints: v0.2 — Semgrep findings to inject as hints.
        variant_seed: v0.3 — variant hunter loop seed.
        agent_mode: "constrained" (legacy 9-tool) or "deep" (full-shell 4+1 tool).
        budget_usd: Per-agent budget in USD (0 = unlimited, bounded by max_steps).
        prompt_mode: "unconstrained" (simple discovery prompt) or "specialist"
                     (legacy prescriptive checklists with execution rules).
        campaign_hint: Optional campaign objective, e.g. "bugs reachable from
                       unauthenticated remote input".
        exploit_mode: When True, append exploit-writing and mitigation-reasoning
                      instructions to the prompt.
        seed_transcript: Summary from a prior run (band promotion). Appended
                         to the prompt so the agent continues from prior work.
        findings_pool: Shared findings pool for cross-agent queries (spec 005).

    Returns:
        (native_hunter, hunter_context). The caller owns the context and
        reads ctx.findings after the run completes.
    """
    tier = file_target.get("tier", "B")
    if specialist is None:
        if tier == "C":
            specialist = "propagation"
        else:
            specialist = _choose_specialist(file_target)

    ctx = HunterContext(
        repo_path=repo_path,
        sandbox=sandbox,
        findings=[],
        file_path=file_target.get("path"),
        session_id=session_id,
        specialist=(
            specialist
            if prompt_mode == "specialist" or specialist == "propagation"
            else "unconstrained"
        ),
        seeded_crash=seeded_crash,
        sandbox_manager=sandbox_manager,
        default_sanitizers=tuple(default_sanitizers),
        findings_pool=findings_pool,
    )

    if specialist == "propagation":
        tools = build_propagation_auditor_tools(ctx)
        prompt = _build_propagation_prompt(file_target)
        max_steps = 20
    elif prompt_mode == "unconstrained":
        combined_hints = list(semgrep_hints or [])
        prompt = _build_unconstrained_prompt(
            file_target,
            project_name,
            seeded_crash,
            combined_hints,
            campaign_hint=campaign_hint,
            exploit_mode=exploit_mode,
            entry_point=entry_point,
            seed_context=seed_context,
            findings_pool=findings_pool,
        )
        if agent_mode == "deep":
            tools = build_deep_agent_tools(ctx)
            max_steps = 500
        else:
            tools = build_hunter_tools(ctx)
            max_steps = 20
    elif agent_mode == "deep":
        tools = build_deep_agent_tools(ctx)
        combined_hints = list(semgrep_hints or [])
        prompt = _build_deep_agent_prompt(
            file_target,
            project_name,
            seeded_crash,
            combined_hints,
            specialist=specialist,
            entry_point=entry_point,
            seed_context=seed_context,
            findings_pool=findings_pool,
        )
        max_steps = 500
    else:
        tools = build_hunter_tools(ctx)
        combined_hints = list(semgrep_hints or [])
        if specialist == "memory_safety":
            combined_hints = _memory_safety_heuristic_hints(repo_path, file_target) + combined_hints
        prompt = _build_hunter_prompt(
            file_target,
            project_name,
            seeded_crash,
            combined_hints,
            specialist=specialist,
        )
        max_steps = 20

    if seed_transcript:
        prompt += "\n\n" + SEED_TRANSCRIPT_BLOCK.format(transcript=seed_transcript)

    return NativeHunter(
        llm=llm,
        prompt=prompt,
        tools=tools,
        ctx=ctx,
        max_steps=max_steps,
        agent_mode=agent_mode,
        budget_usd=budget_usd,
    ), ctx
