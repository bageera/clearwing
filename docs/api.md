# API reference

Auto-generated from docstrings via `mkdocstrings`. The objects
documented here are the ones downstream code is expected to import
directly — internal helpers (`_`-prefixed) are excluded.

## `nightwing.findings`

The canonical unified-finding type plus the converters that bridge
between it and legacy shapes (CICDRunner dicts, SourceAnalyzer
dataclass).

::: nightwing.findings

### The `Finding` dataclass

::: nightwing.findings.types.Finding
    options:
      show_bases: true
      members_order: source

### Converters

::: nightwing.findings.types.from_cicd_dict
::: nightwing.findings.types.to_cicd_dict
::: nightwing.findings.types.from_analysis_finding

## `nightwing.capabilities`

Runtime probing of optional subsystems (guardrails, memory,
telemetry, events, audit, knowledge). The network-pentest graph
calls `capabilities.has(name)` to decide whether to instantiate
each subsystem.

::: nightwing.capabilities
    options:
      members:
        - Capabilities
        - capabilities

## `nightwing.agent.graph`

::: nightwing.agent.graph.build_react_graph
::: nightwing.agent.graph.create_agent
::: nightwing.agent.graph.detect_flags

## `nightwing.agent.tools`

The network-agent tool registry. `get_all_tools()` composes the
63-tool bind-list consumed by `build_react_graph`.

::: nightwing.agent.tools.get_all_tools
::: nightwing.agent.tools.get_custom_tools

### Per-domain tool builders

The seven subpackages each expose their own builders for callers
that want a narrower tool set than the full network-agent bind-list.

::: nightwing.agent.tools.hunt.build_hunter_tools
::: nightwing.agent.tools.hunt.build_propagation_auditor_tools
::: nightwing.agent.tools.hunt.sandbox.HunterContext

## `nightwing.sourcehunt`

### The runner

::: nightwing.sourcehunt.runner.SourceHuntRunner
    options:
      members_order: source
      filters:
        - "!^_"

### Evidence ladder

::: nightwing.sourcehunt.state.EvidenceLevel
::: nightwing.sourcehunt.state.evidence_at_or_above
::: nightwing.sourcehunt.state.evidence_compare
::: nightwing.sourcehunt.state.filter_by_evidence

### Preprocessor + ranker

::: nightwing.sourcehunt.preprocessor.Preprocessor
::: nightwing.sourcehunt.ranker.Ranker

### Hunter pool

::: nightwing.sourcehunt.pool.HunterPool
::: nightwing.sourcehunt.pool.HuntPoolConfig

### Verifier + patch oracle

::: nightwing.sourcehunt.verifier.Verifier
::: nightwing.sourcehunt.verifier.apply_verifier_result
::: nightwing.sourcehunt.patcher.AutoPatcher
::: nightwing.sourcehunt.patcher.apply_patch_attempt

### Mechanism memory

::: nightwing.sourcehunt.mechanism_memory.MechanismStore
::: nightwing.sourcehunt.mechanism_memory.Mechanism
::: nightwing.sourcehunt.mechanism_memory.MechanismExtractor

### Variant loop

::: nightwing.sourcehunt.variant_loop.VariantLoop
::: nightwing.sourcehunt.variant_loop.VariantPatternGenerator
