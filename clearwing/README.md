# Clearwing

Autonomous LLM-driven security testing and vulnerability research platform.

## Warning

Clearwing is a security research tool designed for authorized penetration testing and vulnerability discovery. Always operate within a defined Rules of Engagement (ROE) and with explicit written authorization. Unauthorized access to computer systems is illegal.

## Install

Requires Python 3.11+.

```bash
pip install -e ".[dev]"
```

Or with a virtual environment:

```bash
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

## Quick Start

```bash
# CLI entry point
clearwing --help

# Run a scan
clearwing scan --target example.com
```

## Project Structure

- `agent/` — ReAct-style autonomous pentest agent and tooling
- `sourcehunt/` — Source-code vulnerability hunting pipeline
- `core/` — Engine, config, events, module loader
- `providers/` — LLM provider management (OpenAI, Anthropic, Ollama, etc.)
- `llm/` — Chat abstractions over genai-pyo3
- `scanning/` — Port, service, OS, and vulnerability scanners
- `sandbox/` — Containerized execution environments
- `findings/` — Unified finding types and converters
- `safety/` — Guardrails, audit logging, scoring
- `observability/` — Metrics, telemetry, tracing
- `reporting/` — Report generation and remediation tracking

## Development

```bash
# Lint
ruff check .
ruff format .

# Type check (core / findings / providers / llm)
mypy clearwing/core clearwing/findings clearwing/providers clearwing/llm

# Test
pytest
```

## License

AGPL-3.0-or-later
