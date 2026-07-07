"""Data-driven memory-safety heuristic hints for sourcehunt hunters.

The original inline implementation in ``nightwing.sourcehunt.hunter`` probed
a fixed set of FFmpeg-specific source patterns (``slice_table`` sentinel/counter
collision, ``top_border`` write sink, header width declarations, cross-file
writers/comparators) and emitted up to five structured hints.

This module captures that domain knowledge in a data table so the hunter
remains generic. Behaviour is preserved exactly: for the same inputs the same
hints (in the same order, with the same ``line`` and ``description`` fields) are
returned.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from nightwing.sourcehunt.state import FileTarget

# ---------------------------------------------------------------------------
# Shared line-lookup primitives
# ---------------------------------------------------------------------------


def _first_matching_line(path: Path, pattern: str) -> int | None:
    """Return the 1-based line number of the first line matching ``pattern``.

    Returns ``None`` when the file cannot be read or no line matches.
    """
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line_number, line in enumerate(handle, start=1):
                if re.search(pattern, line):
                    return line_number
    except OSError:
        return None
    return None


# ---------------------------------------------------------------------------
# Data table
# ---------------------------------------------------------------------------
#
# Each entry is a 3-tuple ``(name, regex, target)`` describing a *line lookup*
# that the probes below consume. ``target`` is either:
#   * ``"target"``  -> searched in the target file itself
#   * ``"header"``  -> searched in ``<target_dir>/h264dec.h``
#   * a tuple of sibling file names searched in order (first hit wins)
#
# The probes reference these lookups by name via the ``LOOKUPS`` mapping.


LOOKUPS: list[tuple[str, str, str | tuple[str, ...]]] = [
    ("sentinel_init_line", r"memset\([^;\n]*slice_table[^;\n]*-1", "target"),
    ("sentinel_check_line", r"slice_table\[.*\]\s*==\s*0xFFFF", "target"),
    (
        "counter_assign_line",
        r"sl->slice_num\s*=\s*\+\+h->current_slice",
        "target",
    ),
    (
        "counter_compare_line",
        r"slice_table\[.*\]\s*[!=]=\s*sl->slice_num",
        "target",
    ),
    (
        "top_border_line",
        r"top_border\s*=\s*sl->top_borders\[[^\]]+\]\[sl->mb_x\]",
        "target",
    ),
    ("slice_width_line", r"uint16_t\s*\*\s*slice_table\b", "header"),
    ("current_slice_line", r"\bint\s+current_slice\b", "header"),
    (
        "writer_line",
        r"slice_table\[.*\]\s*=\s*sl->slice_num",
        ("h264_cabac.c", "h264_cavlc.c", "h264_mvpred.h"),
    ),
    (
        "compare_line",
        r"slice_table\[.*\]\s*[!=]=\s*sl->slice_num",
        ("h264_cabac.c", "h264_cavlc.c", "h264_mvpred.h"),
    ),
]


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------
#
# Each probe is ``(name, predicate, build, cwe)``:
#   * ``name``    -- human-readable identifier (debugging only)
#   * ``predicate`` -- ``(lines) -> bool``; when truthy the probe fires
#   * ``build``    -- ``(lines) -> dict[str, Any]``; produces the hint
#   * ``cwe``      -- associated CWE identifier (None when not applicable)


def _build_sentinel_counter_collision(lines: dict[str, int | None]) -> dict[str, Any]:
    sentinel_init_line = lines["sentinel_init_line"]
    sentinel_check_line = lines["sentinel_check_line"]
    counter_assign_line = lines["counter_assign_line"]

    details: list[str] = [f"`slice_table` is sentinel-filled at line {sentinel_init_line}"]
    if sentinel_check_line:
        details.append(f"checked against `0xFFFF` at line {sentinel_check_line}")
    if counter_assign_line:
        details.append(
            f"`sl->slice_num` is incremented from `current_slice` at line {counter_assign_line}"
        )
    return {
        "line": sentinel_init_line,
        "description": "Potential sentinel/counter collision: " + "; ".join(details) + ".",
    }


def _build_counter_alias_check(lines: dict[str, int | None]) -> dict[str, Any]:
    counter_compare_line = lines["counter_compare_line"]
    sentinel_init_line = lines["sentinel_init_line"]
    return {
        "line": counter_compare_line,
        "description": (
            f"`slice_table[...]` is compared to `sl->slice_num` at line {counter_compare_line}; "
            f"check whether that counter can alias the sentinel-filled table state from line "
            f"{sentinel_init_line or '?'}."
        ),
    }


def _build_top_border_sink(lines: dict[str, int | None]) -> dict[str, Any]:
    top_border_line = lines["top_border_line"]
    return {
        "line": top_border_line,
        "description": (
            "Concrete sink cue: `top_border = sl->top_borders[..., sl->mb_x]` is written via "
            f"`AV_COPY*` immediately after line {top_border_line}; if the sentinel/counter "
            "collision breaks the same-slice boundary check at the left edge, follow this path "
            "to a real buffer underflow/overflow rather than stopping at metadata confusion."
        ),
    }


def _build_header_width_check(lines: dict[str, int | None]) -> dict[str, Any]:
    slice_width_line = lines["slice_width_line"]
    current_slice_line = lines["current_slice_line"]
    counter_assign_line = lines["counter_assign_line"]
    sentinel_init_line = lines["sentinel_init_line"]
    return {
        "line": counter_assign_line or sentinel_init_line or 1,
        "description": (
            "Width check: related header `h264dec.h` declares `slice_table` as `uint16_t *` "
            f"(line {slice_width_line}) and `current_slice` as `int` (line {current_slice_line})."
        ),
    }


def _build_cross_file_cue(lines: dict[str, int | None]) -> dict[str, Any]:
    writer_line = lines["writer_line"]
    compare_line = lines["compare_line"]
    counter_assign_line = lines["counter_assign_line"]
    sentinel_init_line = lines["sentinel_init_line"]

    related_bits: list[str] = []
    if writer_line:
        related_bits.append(
            f"related decode paths write `slice_table[mb_xy] = sl->slice_num` (line {writer_line})"
        )
    if compare_line:
        related_bits.append(
            f"neighbor/cache logic compares `slice_table[...]` to `sl->slice_num` (line {compare_line})"
        )
    return {
        "line": counter_assign_line or sentinel_init_line or 1,
        "description": "Cross-file cue: " + "; ".join(related_bits) + ".",
    }


PROBES: list[
    tuple[
        str,
        Callable[[dict[str, int | None]], bool],
        Callable[[dict[str, int | None]], dict[str, Any]],
        str | None,
    ]
] = [
    (
        "sentinel_counter_collision",
        lambda L: bool(
            L["sentinel_init_line"] and (L["sentinel_check_line"] or L["counter_assign_line"])
        ),
        _build_sentinel_counter_collision,
        "CWE-193",
    ),
    (
        "counter_alias_check",
        lambda L: bool(L["counter_compare_line"] and L["counter_assign_line"]),
        _build_counter_alias_check,
        "CWE-193",
    ),
    (
        "top_border_sink",
        lambda L: bool(L["top_border_line"] and L["counter_compare_line"]),
        _build_top_border_sink,
        "CWE-787",
    ),
    (
        "header_width_check",
        lambda L: bool(L["slice_width_line"] and L["current_slice_line"]),
        _build_header_width_check,
        "CWE-193",
    ),
    (
        "cross_file_cue",
        lambda L: bool(L["writer_line"] or L["compare_line"]),
        _build_cross_file_cue,
        "CWE-193",
    ),
]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

_MAX_HINTS = 5


def derive_memory_safety_hints(
    repo_path: str,
    file_target: FileTarget,
) -> list[dict[str, Any]]:
    """Derive high-signal, file-local hints for memory-safety hunters.

    The goal is not to prove a bug statically here; it is to surface concrete
    candidate mechanisms already visible in the source tree so the hunter does
    not get stuck on generic memcpy noise.
    """

    target_rel = str(file_target.get("path") or "")
    if not target_rel:
        return []

    target_path = Path(repo_path) / target_rel
    if not target_path.is_file():
        return []

    header_path = target_path.parent / "h264dec.h"

    lines: dict[str, int | None] = {}
    for name, pattern, target in LOOKUPS:
        if target == "target":
            lines[name] = _first_matching_line(target_path, pattern)
        elif target == "header":
            lines[name] = _first_matching_line(header_path, pattern)
        else:
            # tuple of sibling file names — first hit wins
            found: int | None = None
            for sibling in target:
                found = _first_matching_line(target_path.parent / sibling, pattern)
                if found is not None:
                    break
            lines[name] = found

    hints: list[dict[str, Any]] = []
    for _name, predicate, build, _cwe in PROBES:
        if predicate(lines):
            hints.append(build(lines))
        if len(hints) >= _MAX_HINTS:
            break

    return hints[:_MAX_HINTS]
