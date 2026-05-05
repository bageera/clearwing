"""Runtime capability detection for optional clearwing subsystems.

The network-agent graph gates a handful of features on subsystem
availability: memory summarization, event-bus publishing, telemetry
cost tracking, audit logging, knowledge-graph population, and input/
output guardrails. Each of these subsystems is currently part of the
base install, but we want a single point of truth for "is this
subsystem actually importable in the current process" so that:

1. Stripped / partial installs degrade gracefully rather than crashing
   on first use.
2. Future moves of any subsystem to `[project.optional-dependencies]`
   just work — no graph.py changes needed beyond flipping the extras
   metadata.
3. The graph's import section stays unconditional, so static analysis
   tools (ruff/mypy) see real symbols instead of `Optional[None]`
   fallbacks.

Usage:
    from clearwing.capabilities import capabilities
    if capabilities.has("memory"):
        episodic_memory = EpisodicMemory(session_id)

The `capabilities` object is a frozen singleton computed once at
import time. Every probe runs inside its own try/except ImportError
so a missing one doesn't take the rest down.
"""

from __future__ import annotations

from dataclasses import dataclass

# name → fully-qualified module to try importing
_CAPABILITY_MAP: dict[str, str] = {
    "guardrails": "clearwing.safety.guardrails",
    "memory": "clearwing.data.memory",
    "telemetry": "clearwing.observability.telemetry",
    "events": "clearwing.core.events",
    "audit": "clearwing.safety.audit",
    "knowledge": "clearwing.data.knowledge",
}


def _detect_installed() -> frozenset[str]:
    installed: set[str] = set()
    for name, module in _CAPABILITY_MAP.items():
        try:
            __import__(module)
            installed.add(name)
        except ImportError:
            pass
    return frozenset(installed)


@dataclass(frozen=True)
class Capabilities:
    """Frozen snapshot of subsystems importable in this process."""

    installed: frozenset[str]

    def has(self, name: str) -> bool:
        """True if the named subsystem is available in this process."""
        return name in self.installed


capabilities = Capabilities(installed=_detect_installed())


__all__ = ["Capabilities", "capabilities"]
