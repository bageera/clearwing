from __future__ import annotations

from nightwing.safety.scoring.cvss import VULN_PRESETS, CVSSCalculator, CVSSVector
from nightwing.safety.scoring.dedup import DedupRecord, FindingDeduplicator

__all__ = [
    "CVSSVector",
    "CVSSCalculator",
    "VULN_PRESETS",
    "DedupRecord",
    "FindingDeduplicator",
]
