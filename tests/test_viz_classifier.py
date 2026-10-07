"""Tests for nightwing.reporting.viz_classifier (McCandless taxonomy)."""

from __future__ import annotations

from nightwing.reporting.viz_classifier import (
    Component,
    ObservationType,
    classify,
    classify_one,
    render_component,
    sparkline,
)


def _mk(**obs):
    return obs


class TestArchetypes:
    def test_explicit_type_wins(self):
        c = classify_one(_mk(metric="x", viz_type="ranking", items=[{"label": "a", "value": 1}]))
        assert c.obs_type is ObservationType.RANKING
        assert c.confidence == 1.0

    def test_invalid_explicit_type_falls_to_narrative(self):
        c = classify_one(_mk(metric="x", viz_type="pie_chart_of_doom"))
        assert c.obs_type is ObservationType.NARRATIVE

    def test_trend_beats_distribution_on_ordered_hint(self):
        c = classify_one(_mk(metric="findings_per_run", series=[3, 5, 4, 9]))
        assert c.obs_type is ObservationType.TREND
        assert c.component is Component.SPARKLINE

    def test_flat_unordered_series_is_distribution(self):
        c = classify_one(_mk(metric="exec_ms", series=[5.0] * 12))
        assert c.obs_type is ObservationType.DISTRIBUTION

    def test_two_groups_is_comparison(self):
        c = classify_one(
            _mk(
                metric="cost",
                items=[{"label": "kali", "value": 4.2}, {"label": "parrot", "value": 9.1}],
            )
        )
        assert c.obs_type is ObservationType.COMPARISON

    def test_many_labeled_items_is_ranking(self):
        c = classify_one(
            _mk(metric="cwe_hist", items=[{"label": f"cwe{i}", "value": 10 - i} for i in range(8)])
        )
        assert c.obs_type is ObservationType.RANKING

    def test_composition_requires_whole_declared(self):
        # same spread as ranking unless declared / named a split
        c = classify_one(
            _mk(
                metric="cost_split",
                of_total=True,
                items=[
                    {"label": "s1", "value": 30},
                    {"label": "s2", "value": 25},
                    {"label": "s3", "value": 25},
                    {"label": "s4", "value": 20},
                ],
            )
        )
        assert c.obs_type is ObservationType.COMPOSITION

    def test_relationship_needs_correlated_points(self):
        c = classify_one(
            _mk(metric="loc_vs_findings", points=[{"x": x, "y": 2 * x + 1} for x in range(10)])
        )
        assert c.obs_type is ObservationType.RELATIONSHIP
        assert "10 points" in c.reason and "|r|=1.00" in c.reason

    def test_threshold_declared_and_breached(self):
        c = classify_one(_mk(metric="budget_usd", limit=10, series=[4, 9, 12]))
        assert c.obs_type is ObservationType.THRESHOLD
        assert "BREACHED" in render_component(c)

    def test_threshold_not_breached(self):
        c = classify_one(_mk(metric="budget_usd", limit=10, series=[4]))
        assert c.obs_type is ObservationType.THRESHOLD
        assert "ok" in render_component(c)

    def test_anomaly_4x_median(self):
        c = classify_one(
            _mk(
                metric="run_cost",
                items=[
                    {"label": "a", "value": 2},
                    {"label": "b", "value": 2},
                    {"label": "c", "value": 3},
                    {"label": "d", "value": 40},
                ],
            )
        )
        assert c.obs_type is ObservationType.ANOMALY
        assert "⚠" in render_component(c)

    def test_geographic_by_name(self):
        c = classify_one(
            _mk(
                metric="findings_by_region",
                items=[{"label": "us-east", "value": 3}, {"label": "eu", "value": 1}],
            )
        )
        assert c.obs_type is ObservationType.GEOGRAPHIC

    def test_geographic_by_keys(self):
        c = classify_one(_mk(metric="sites", country="US", items=[{"label": "host1", "value": 1}]))
        assert c.obs_type is ObservationType.GEOGRAPHIC

    def test_narrative_fallback(self):
        c = classify_one(_mk(metric="scope_note", headline="14 findings"))
        assert c.obs_type is ObservationType.NARRATIVE
        assert "14 findings" in render_component(c)


class TestBatch:
    def test_classify_preserves_order_and_length(self):
        obs = [
            _mk(metric="a", series=[1, 2, 3]),
            _mk(metric="b", headline="x"),
            _mk(
                metric="c",
                items=[
                    {"label": "t1", "value": 1},
                    {"label": "t2", "value": 2},
                    {"label": "t3", "value": 3},
                    {"label": "t4", "value": 4},
                ],
            ),
        ]
        out = classify(obs)
        assert [o.metric for o in out] == ["a", "b", "c"]
        assert [o.obs_type for o in out] == [
            ObservationType.TREND,
            ObservationType.NARRATIVE,
            ObservationType.RANKING,
        ]

    def test_every_type_maps_to_component(self):
        for t in ObservationType:
            assert t in {
                c.obs_type
                for c in classify(
                    [
                        _mk(metric="t", series=[1, 2, 3], viz_type=t.value),
                    ]
                )
            }


class TestRender:
    def test_trend_renders_sparkline(self):
        c = classify_one(_mk(metric="fpr", series=[3, 5, 4, 9]))
        out = render_component(c)
        assert "▁" in out and "█" in out and "(Δ +6)" in out

    def test_one_extreme_item_is_anomaly_not_ranking(self):
        # 99 is 33x median — anomaly callout outranks the leader-board by design
        c = classify_one(
            _mk(
                metric="r",
                items=[
                    {"label": f"item{i:02}", "value": v}
                    for i, v in enumerate([40, 2, 30, 1, 10, 5, 3, 2, 1, 1, 99])
                ],
            )
        )
        assert c.obs_type is ObservationType.ANOMALY

    def test_ranking_is_sorted_and_bounded(self):
        # steep but not outlier-slope data (max 2.1x median) — reads as a board
        c = classify_one(
            _mk(
                metric="r",
                items=[
                    {"label": f"item{i:02}", "value": v}
                    for i, v in enumerate([40, 35, 32, 28, 25, 22, 20, 18, 16, 15, 12, 10, 8, 6])
                ],
            )
        )
        assert c.obs_type is ObservationType.RANKING
        out = render_component(c)
        assert out.count("\n") == 9  # top 10 only
        assert out.splitlines()[0].startswith("1. ")  # sorted desc

    def test_composition_percentages_sum_to_100ish(self):
        c = classify_one(
            _mk(
                metric="split",
                of_total=True,
                items=[
                    {"label": "a", "value": 1},
                    {"label": "b", "value": 1},
                    {"label": "c", "value": 1},
                    {"label": "d", "value": 1},
                ],
            )
        )
        assert "25%" in render_component(c)

    def test_empty_series_sparkline(self):
        assert sparkline([]) == ""
