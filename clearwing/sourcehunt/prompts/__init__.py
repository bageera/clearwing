"""Prompt templates and builders for the sourcehunt hunter.

Specialist prompt constants live in :mod:`clearwing.sourcehunt.prompts.specialists`
and the prompt-builder functions live in
:mod:`clearwing.sourcehunt.prompts.builders`.
"""

from __future__ import annotations

from .builders import (
    _build_deep_agent_prompt,
    _build_hunter_prompt,
    _build_propagation_prompt,
    _build_subsystem_prompt,
    _build_unconstrained_prompt,
)
from .specialists import (
    _DEEP_SPECIALIST_FOCUS,
    _SPECIALIST_PROMPTS,
    CAMPAIGN_HINT_TEMPLATE,
    CRYPTO_PRIMITIVE_HUNTER_PROMPT,
    DEEP_AGENT_PROMPT,
    DISCOVERY_PROMPT,
    ENTRY_POINT_FOCUS,
    EXPLOIT_EXTENSION,
    GENERAL_HUNTER_PROMPT,
    HUNTER_EXECUTION_RULES,
    KERNEL_SYSCALL_HUNTER_PROMPT,
    LOGIC_AUTH_HUNTER_PROMPT,
    MEMORY_SAFETY_HUNTER_PROMPT,
    MITIGATION_REASONING,
    POOL_ACCESS_BLOCK,
    PROPAGATION_AUDIT_PROMPT,
    SEED_CORPUS_BLOCK,
    SEED_TRANSCRIPT_BLOCK,
    SELF_CHECK,
    SUBSYSTEM_HUNT_PROMPT,
    WEB_FRAMEWORK_HUNTER_PROMPT,
)

__all__ = [
    "CAMPAIGN_HINT_TEMPLATE",
    "CRYPTO_PRIMITIVE_HUNTER_PROMPT",
    "DEEP_AGENT_PROMPT",
    "DISCOVERY_PROMPT",
    "ENTRY_POINT_FOCUS",
    "EXPLOIT_EXTENSION",
    "GENERAL_HUNTER_PROMPT",
    "HUNTER_EXECUTION_RULES",
    "KERNEL_SYSCALL_HUNTER_PROMPT",
    "LOGIC_AUTH_HUNTER_PROMPT",
    "MEMORY_SAFETY_HUNTER_PROMPT",
    "MITIGATION_REASONING",
    "POOL_ACCESS_BLOCK",
    "PROPAGATION_AUDIT_PROMPT",
    "SEED_CORPUS_BLOCK",
    "SEED_TRANSCRIPT_BLOCK",
    "SELF_CHECK",
    "SUBSYSTEM_HUNT_PROMPT",
    "WEB_FRAMEWORK_HUNTER_PROMPT",
    "_DEEP_SPECIALIST_FOCUS",
    "_SPECIALIST_PROMPTS",
    "_build_deep_agent_prompt",
    "_build_hunter_prompt",
    "_build_propagation_prompt",
    "_build_subsystem_prompt",
    "_build_unconstrained_prompt",
]
