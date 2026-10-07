"""Observation classifier + reporting-component chooser (McCandless-style).

Applies the "Information is Beautiful" taxonomy to pipeline observations:
each observation is classified as one of ten viz archetypes

    TREND, COMPARISON, RANKING, DISTRIBUTION, RELATIONSHIP,
    COMPOSITION, GEOGRAPHIC, ANOMALY, THRESHOLD, NARRATIVE

and mapped to a concrete reporting component (rich table, unicode
sparkline/bar, BLUF line, callout, ...). Heuristics only inspect the
values the caller supplies — no LLM call, stdlib only.

    from nightwing.reporting.viz_classifier import classify, render_component

    obs = classify([
        {"metric": "findings_per_run", "series": [3, 5, 4, 9]},
        {"metric": "cost_by_tier", "items": [{"label": "t1", "value": 4.2},
                                             {"label": "t2", "value": 9.1}]},
    ])
    for o in obs:
        print(o.obs_type, o.component)
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = [
    "ObservationType",
    "Component",
    "VizClassification",
    "classify",
    "classify_one",
    "render_component",
    "sparkline",
]


class ObservationType(str, Enum):
    """McCandless viz archetypes, in classifier-preference order."""

    TREND = "trend"
    COMPARISON = "comparison"
    RANKING = "ranking"
    DISTRIBUTION = "distribution"
    RELATIONSHIP = "relationship"
    COMPOSITION = "composition"
    GEOGRAPHIC = "geographic"
    ANOMALY = "anomaly"
    THRESHOLD = "threshold"
    NARRATIVE = "narrative"


class Component(str, Enum):
    """Concrete reporting components available in Nightwing output."""

    # ordered stream over time — unicode sparkline + delta line
    SPARKLINE = "sparkline"
    # side-by-side two-group delta table
    COMPARISON_TABLE = "comparison_table"
    # sorted leader-board rows
    RANKED_LIST = "ranked_list"
    # min/median/p90/max + histogram stem row
    HISTOGRAM = "histogram"
    # paired XY table with correlation line
    SCATTER_CORRELATION = "scatter_correlation"
    # parts-of-a-whole stacked bars
    STACKED_BAR = "stacked_bar"
    # per-asset/location mapping table
    GEO_TABLE = "geo_table"
    # the one-off outlier callout
    OUTLIER_CALLOUT = "outlier_callout"
    # state vs. limit gauge line
    GAUGE = "gauge"
    # single BLUF sentence / event log line
    BLUF_LINE = "bluf_line"


@dataclass
class VizClassification:
    """Classification of one observation into archetype + component."""

    metric: str
    obs_type: ObservationType
    component: Component
    reason: str  # one-line explanation of the chosen heuristic
    confidence: float  # 0..1, cheap self-report for tuning
    data: dict[str, Any] = field(default_factory=dict)


# --- primitives ---------------------------------------------------------------

_TREND_HINTS = ("per_run", "over_time", "delta", "daily", "timeline", "trend", "rate")
_GEO_HINTS = ("country", "region", "geo", "lat", "lon", "site", "location", "host", "host_")


def _numeric_series(obs: dict[str, Any]) -> list[float]:
    for key in ("series", "values", "samples"):
        v = obs.get(key)
        if isinstance(v, list):
            vals = [float(x) for x in v if isinstance(x, int | float)]
            if vals:
                return vals
    v = obs.get("history")
    if isinstance(v, list):
        vals = [
            float(x["value"])
            for x in v
            if isinstance(x, dict) and isinstance(x.get("value"), int | float)
        ]
        if vals:
            return vals
    return []


def _item_pairs(obs: dict[str, Any]) -> list[tuple[str, float]]:
    items = obs.get("items")
    if not isinstance(items, list):
        return []
    pairs: list[tuple[str, float]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        label = str(it.get("label") or it.get("name") or it.get("id") or "")
        raw = it.get("value", it.get("count", it.get("cost")))
        if label and isinstance(raw, int | float):
            pairs.append((label, float(raw)))
    return pairs


def _xy_pairs(obs: dict[str, Any]) -> list[tuple[float, float]]:
    points = obs.get("points")
    if not isinstance(points, list):
        return []
    out = []
    for p in points:
        if (
            isinstance(p, dict)
            and isinstance(p.get("x"), int | float)
            and isinstance(p.get("y"), int | float)
        ):
            out.append((float(p["x"]), float(p["y"])))
    return out


def _cv(values: list[float]) -> float:
    """Coefficient of variation; 0 for constant data."""
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    if mean == 0:
        return 0.0 if max(values) == min(values) else math.inf
    return statistics.pstdev(values) / mean


# --- the classifier -----------------------------------------------------------


def classify_one(obs: dict[str, Any]) -> VizClassification:
    """Classify a single observation dict. Explicit type wins; else heuristics."""
    metric = str(obs.get("metric") or obs.get("name") or "observation")
    explicit = obs.get("viz_type") or obs.get("observation_type")
    if explicit:
        try:
            t = ObservationType(str(explicit).lower())
        except ValueError:
            t = ObservationType.NARRATIVE
        return VizClassification(
            metric=metric,
            obs_type=t,
            component=_COMPONENT_FOR[t],
            reason="explicit",
            confidence=1.0,
            data=obs,
        )

    series = _numeric_series(obs)
    pairs = _item_pairs(obs)
    xy = _xy_pairs(obs)
    metric_l = metric.lower()

    hit = _classify_named_rules(metric, obs, metric_l, series, pairs, xy)
    if hit is not None:
        return hit

    # Trend: ordered series with movement + trend-ish name.
    if len(series) >= 3:
        moving = _cv(series) > 0.15
        delta = series[-1] - series[0]
        if moving and (delta != 0 or any(h in metric_l for h in _TREND_HINTS)):
            return _mk(
                metric,
                ObservationType.TREND,
                obs,
                f"{len(series)} points, cv={_cv(series):.2f}, delta={delta:+g}",
            )

    # Composition: labeled parts summing to a whole — but only when the caller
    # declares it (of_total=True/total) or the metric names a split/share;
    # otherwise a spread of labeled values reads as a ranking.
    if len(pairs) >= 2 and (
        obs.get("of_total") is True or obs.get("total") is not None or _composition_word(metric_l)
    ):
        total = obs.get("total")
        if total is None and pairs:
            total = sum(v for _, v in pairs)  # assume parts make the whole
        if total and all(v / total <= 0.6 for _, v in pairs):
            return _mk(
                metric,
                ObservationType.COMPOSITION,
                obs,
                f"{len(pairs)} parts, largest ≤ 60% of {total:g}",
            )

    # Ranking vs comparison: ranking = many labeled items sorted for priority;
    # comparison = 2-3 groups side by side.
    if pairs:
        if len(pairs) >= 4:
            return _mk(metric, ObservationType.RANKING, obs, f"{len(pairs)} labeled items")
        return _mk(metric, ObservationType.COMPARISON, obs, f"{len(pairs)} groups side-by-side")

    # Distribution: a spread with no order story.
    if len(series) >= 5:
        return _mk(
            metric, ObservationType.DISTRIBUTION, obs, f"{len(series)} samples, no order/story"
        )

    # Narrative fallback: anything without numeric substance.
    return _mk(metric, ObservationType.NARRATIVE, obs, "no numeric shape detected")


def classify(observations: list[dict[str, Any]]) -> list[VizClassification]:
    """Classify a batch of observations."""
    return [classify_one(o) for o in observations]


def _classify_named_rules(
    metric: str,
    obs: dict[str, Any],
    metric_l: str,
    series: list[float],
    pairs: list[tuple[str, float]],
    xy: list[tuple[float, float]],
) -> VizClassification | None:
    """Keyword- and structure-driven rules: geo, relationship, threshold, anomaly."""
    # Geographic: label/keyword driven.
    if any(h in metric_l for h in _GEO_HINTS) or _has_geo_keys(obs):
        return _mk(metric, ObservationType.GEOGRAPHIC, obs, "geo keys/hints in name")

    # Relationship: explicitly paired XY with enough points.
    if len(xy) >= 5:
        r = _correlation(xy)
        if abs(r) >= 0.6:
            return _mk(
                metric, ObservationType.RELATIONSHIP, obs, f"{len(xy)} points, |r|={abs(r):.2f}"
            )
        # weakly correlated XY — fall through.

    # Threshold: caller-declared limit, or a "budget/alert/quota" name.
    if (
        obs.get("limit") is not None
        or obs.get("threshold") is not None
        or _threshold_word(metric_l)
    ):
        limit_raw = obs.get("limit", obs.get("threshold"))
        limit = float(limit_raw) if isinstance(limit_raw, int | float) else None
        breached = (max(series) > limit) if (limit is not None and series) else None
        return _mk(
            metric,
            ObservationType.THRESHOLD,
            obs,
            "limit declared" + (", breached" if breached else ""),
        )

    # Anomaly: a single value standing far out (≥ 6× median) — the McCandless
    # outlier callout. 4× fired too readily on naturally skewed cost data; 6×
    # keeps the callout for genuinely visually-obvious outliers.
    if pairs and len(pairs) >= 4:
        vals = [v for _, v in pairs]
        med = statistics.median(vals)
        top_label, top_val = max(pairs, key=lambda kv: kv[1])
        if med > 0 and top_val >= med * 6:
            return _mk(
                metric,
                ObservationType.ANOMALY,
                obs,
                f"'{top_label}' ≥ 6× median ({top_val:g} vs {med:g})",
            )
    if "outlier" in metric_l or "anomaly" in metric_l:
        return _mk(metric, ObservationType.ANOMALY, obs, "anomaly keyword")
    return None


def _mk(metric: str, t: ObservationType, data: dict, reason: str) -> VizClassification:
    return VizClassification(
        metric=metric,
        obs_type=t,
        component=_COMPONENT_FOR[t],
        reason=reason,
        confidence=_CONFIDENCE.get(t, 0.5),
        data=data,
    )


def _has_geo_keys(obs: dict[str, Any]) -> bool:
    return any(k in obs for k in ("country", "region", "site", "location", "lat"))


def _threshold_word(metric_l: str) -> bool:
    return any(w in metric_l for w in ("budget", "limit", "quota", "alert", "cap"))


def _composition_word(metric_l: str) -> bool:
    return any(
        w in metric_l
        for w in ("split", "share", "breakdown", "composition", "of_total", "percentage")
    )


def _correlation(xy: list[tuple[float, float]]) -> float:
    n = len(xy)
    if n < 3:
        return 0.0
    mx = sum(x for x, _ in xy) / n
    my = sum(y for _, y in xy) / n
    sxx = sum((x - mx) ** 2 for x, _ in xy)
    syy = sum((y - my) ** 2 for _, y in xy)
    if sxx == 0 or syy == 0:
        return 0.0
    sxy = sum((x - mx) * (y - my) for x, y in xy)
    return sxy / math.sqrt(sxx * syy)


_COMPONENT_FOR: dict[ObservationType, Component] = {
    ObservationType.TREND: Component.SPARKLINE,
    ObservationType.COMPARISON: Component.COMPARISON_TABLE,
    ObservationType.RANKING: Component.RANKED_LIST,
    ObservationType.DISTRIBUTION: Component.HISTOGRAM,
    ObservationType.RELATIONSHIP: Component.SCATTER_CORRELATION,
    ObservationType.COMPOSITION: Component.STACKED_BAR,
    ObservationType.GEOGRAPHIC: Component.GEO_TABLE,
    ObservationType.ANOMALY: Component.OUTLIER_CALLOUT,
    ObservationType.THRESHOLD: Component.GAUGE,
    ObservationType.NARRATIVE: Component.BLUF_LINE,
}

_CONFIDENCE: dict[ObservationType, float] = {
    ObservationType.TREND: 0.7,  # cv>0.15 + delta is a decent but tunable signal
    ObservationType.COMPARISON: 0.8,
    ObservationType.RANKING: 0.8,
    ObservationType.DISTRIBUTION: 0.7,
    ObservationType.RELATIONSHIP: 0.9,
    ObservationType.COMPOSITION: 0.6,  # parts-summing assumption is the softest rule
    ObservationType.GEOGRAPHIC: 0.9,
    ObservationType.ANOMALY: 0.8,
    ObservationType.THRESHOLD: 0.9,
    ObservationType.NARRATIVE: 0.4,  # fallback bucket
}


# --- component renderers (plain text / unicode, no new deps) ------------------

_SPARK_BLOCKS = "▁▂▃▄▅▆▇█"


def sparkline(values: list[float], width: int = 0) -> str:
    """Unicode sparkline for a numeric series (McCandless trend row)."""
    if not values:
        return ""
    if width and len(values) > width:
        step = len(values) / width
        values = [values[int(i * step)] for i in range(width)]
    lo, hi = min(values), max(values)
    if hi == lo:
        return "".join(_SPARK_BLOCKS[3] * len(values))
    scaled = [int((v - lo) / (hi - lo) * (len(_SPARK_BLOCKS) - 1)) for v in values]
    return "".join(_SPARK_BLOCKS[i] for i in scaled)


def render_component(c: VizClassification) -> str:
    """Render the chosen component for one classification as plain text."""
    t = c.obs_type
    series = _numeric_series(c.data)
    pairs = _item_pairs(c.data)

    if t is ObservationType.TREND and series:
        delta = series[-1] - series[0]
        return f"{c.metric}  {sparkline(series, width=40)}  (Δ {delta:+g})"

    if t is ObservationType.COMPARISON and pairs:
        a, b = pairs[0], pairs[1]
        diff = b[1] - a[1]
        pct = f" ({diff / a[1] * 100:+.0f}%)" if a[1] else ""
        return f"{c.metric}: {a[0]}={a[1]:g} vs {b[0]}={b[1]:g} → Δ {diff:+g}{pct}"

    if t is ObservationType.RANKING and pairs:
        rows = sorted(pairs, key=lambda kv: -kv[1])
        lines = [
            f"{i + 1}. {lbl:<28} {'█' * max(1, int(v / rows[0][1] * 30))} {v:g}"
            for i, (lbl, v) in enumerate(rows[:10])
        ]
        return "\n".join(lines)

    if t is ObservationType.DISTRIBUTION and series:
        return (
            f"{c.metric}  min={min(series):g} med={statistics.median(series):g} "
            f"p90={_p90(series):g} max={max(series):g}  {_stem_hist(series)}"
        )

    if t is ObservationType.RELATIONSHIP:
        xy = _xy_pairs(c.data)
        r = _correlation(xy) if len(xy) >= 3 else 0.0
        return f"{c.metric}: n={len(xy)} r={r:+.2f} ({_corr_word(r)})"

    if t is ObservationType.COMPOSITION and pairs:
        total = sum(v for _, v in pairs) or 1
        return " + ".join(f"{lbl} {v / total * 100:.0f}%" for lbl, v in pairs)

    if t is ObservationType.GEOGRAPHIC:
        if pairs:
            return "\n".join(
                f"  {lbl:<28} {v:g}" for lbl, v in sorted(pairs, key=lambda kv: -kv[1])[:10]
            )
        return f"{c.metric}: geographic dimension present (see data)"

    if t is ObservationType.ANOMALY:
        if pairs:
            lbl, v = max(pairs, key=lambda kv: kv[1])
            med = statistics.median([x for _, x in pairs])
            factor = f"{v / med:.1f}× median" if med else ""
            return f"⚠ {c.metric}: '{lbl}' = {v:g} ({factor})"
        return f"⚠ {c.metric}: outlier present (see data)"

    if t is ObservationType.THRESHOLD:
        limit_raw = c.data.get("limit", c.data.get("threshold"))
        cur = max(series) if series else None
        if isinstance(limit_raw, int | float) and cur is not None:
            pct = cur / limit_raw * 100 if limit_raw else 0
            flag = "⚠ BREACHED" if cur > limit_raw else "ok"
            return f"{c.metric}: {cur:g}/{limit_raw:g} ({pct:.0f}%) {flag}"
        return f"{c.metric}: threshold declared ({limit_raw})"

    # NARRATIVE → BLUF
    return f"{c.metric}: {c.data.get('headline') or c.data.get('summary') or _summarize(c)}"


# --- text helpers -------------------------------------------------------------


def _p90(values: list[float]) -> float:
    s = sorted(values)
    idx = min(len(s) - 1, math.ceil(0.9 * len(s)) - 1)
    return s[max(0, idx)]


def _stem_hist(values: list[float], bins: int = 8) -> str:
    if not values:
        return ""
    lo, hi = min(values), max(values)
    if hi == lo:
        return "▇" * bins
    counts = [0] * bins
    for v in values:
        idx = min(bins - 1, int((v - lo) / (hi - lo + 1e-12) * bins))
        counts[idx] += 1
    peak = max(counts) or 1
    return "".join("▇" * max(1, int(n / peak * 5)) + " " for n in counts)


def _corr_word(r: float) -> str:
    if abs(r) < 0.3:
        return "no linear relation"
    word = "positive" if r > 0 else "negative"
    return f"{'strong' if abs(r) > 0.8 else 'moderate'} {word} correlation"


def _summarize(c: VizClassification) -> str:
    pairs = _item_pairs(c.data)
    if pairs:
        top = max(pairs, key=lambda kv: kv[1])
        return f"narrative context; largest item {top[0]}={top[1]:g}"
    return "narrative context (no numeric shape)"


# --- self-check ---------------------------------------------------------------

if __name__ == "__main__":
    # trend beats distribution: ordered series with a name hint
    c = classify_one({"metric": "findings_per_run", "series": [3, 5, 4, 9]})
    assert c.obs_type is ObservationType.TREND, c
    # 2 groups = comparison; 8 labeled = ranking
    c = classify_one(
        {
            "metric": "cost",
            "items": [{"label": "kali", "value": 4.2}, {"label": "parrot", "value": 9.1}],
        }
    )
    assert c.obs_type is ObservationType.COMPARISON, c
    c = classify_one(
        {"metric": "cwe_hist", "items": [{"label": f"cwe{i}", "value": 10 - i} for i in range(8)]}
    )
    assert c.obs_type is ObservationType.RANKING, c
    # composition when parts sum to a whole with no dominant part
    c = classify_one(
        {
            "metric": "cost_split",
            "items": [
                {"label": "s1", "value": 30},
                {"label": "s2", "value": 25},
                {"label": "s3", "value": 25},
                {"label": "s4", "value": 20},
            ],
        }
    )
    assert c.obs_type is ObservationType.COMPOSITION, c
    # correlation XY
    c = classify_one(
        {"metric": "loc_vs_findings", "points": [{"x": x, "y": x * 2 + 1} for x in range(10)]}
    )
    assert (
        c.obs_type is ObservationType.RELATIONSHIP and c.component is Component.SCATTER_CORRELATION
    ), c
    # threshold declared + breached
    c = classify_one({"metric": "budget_usd", "limit": 10, "series": [4, 9, 12]})
    assert c.obs_type is ObservationType.THRESHOLD and "BREACHED" in render_component(c), c
    # 6x median outlier
    c = classify_one(
        {
            "metric": "run_cost",
            "items": [
                {"label": "a", "value": 2},
                {"label": "b", "value": 2},
                {"label": "c", "value": 3},
                {"label": "d", "value": 40},
            ],
        }
    )
    assert c.obs_type is ObservationType.ANOMALY, c
    # geographic keyword
    c = classify_one(
        {
            "metric": "findings_by_region",
            "items": [{"label": "us-east", "value": 3}, {"label": "eu", "value": 1}],
        }
    )
    assert c.obs_type is ObservationType.GEOGRAPHIC, c
    # flat series, no hints → distribution (many samples, no story)
    c = classify_one({"metric": "exec_ms", "series": [5.0] * 10 + [5.1, 4.9]})
    assert c.obs_type is ObservationType.DISTRIBUTION, c
    # narrative fallback
    c = classify_one({"metric": "scope_note", "note": "see LOA"})
    assert c.obs_type is ObservationType.NARRATIVE, c
    # explicit override wins
    c = classify_one(
        {
            "metric": "x",
            "series": [1, 2, 3],
            "viz_type": "ranking",
            "items": [{"label": "a", "value": 1}],
        }
    )
    assert c.obs_type is ObservationType.RANKING and c.confidence == 1.0, c
    # sparkline sanity: min→lowest block, mid→middle, max→highest
    s = sparkline([1, 2, 3])
    assert s[0] == _SPARK_BLOCKS[0] and s[1] == _SPARK_BLOCKS[3] and s[2] == _SPARK_BLOCKS[7], s
    print("viz_classifier self-check OK")
