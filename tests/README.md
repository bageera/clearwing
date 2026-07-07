# Nightwing Tests

This directory contains test cases for Nightwing modules.

## Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage (term + html)
make test-coverage

# Parallel execution (fastest)
make test-parallel

# Strict CI mode
make test-strict

# Specific test file
pytest tests/test_scanners.py

# Specific test
pytest tests/test_scanners.py::TestPortScanner::test_syn_scan

# With verbose output
pytest tests/ -v

# Run tests matching a pattern
pytest tests/ -k "sourcehunt"
```

## Test Categories

The test suite is organized by type:

| Category | Location | Description |
|----------|----------|-------------|
| Unit | `tests/` (root) | Fast, isolated, no I/O |
| Integration | `tests/` | Real DB, real API mocks, Docker containers |
| E2E | `tests/` | Full CLI runs, container lifecycle |

## Fixtures

Shared fixtures are in `tests/fixtures/`. Import via:

```python
from tests.fixtures import *  # noqa: F401,F403
```

## Coverage

Generate HTML coverage report:

```bash
make test-coverage
# or manually:
pytest --cov=nightwing --cov-report=term-missing --cov-report=html
# view at:
open htmlcov/index.html
```

Coverage threshold: **50%** (enforced in CI via `coverage report --fail-under=50`)

## Hypothesis (Property-Based Testing)

Hypothesis is configured with `--hypothesis-show-statistics`. To enable:

```bash
pytest --hypothesis-seed=0
```

## Test Ordering

`pytest-randomly` shuffles tests each run to catch order dependencies. To reproduce a specific order:

```bash
pytest -p randomly --randomly-seed=12345
```

## Tooling

| Tool | Purpose |
|------|---------|
| `pytest` | Test runner |
| `pytest-asyncio` | Async test support |
| `pytest-cov` | Coverage plugin |
| `pytest-xdist` | Parallel test execution |
| `pytest-httpx` | HTTP mocking |
| `pytest-randomly` | Test order shuffling |
| `coverage` | Coverage measurement |
| `hypothesis` | Property-based testing |
| `dirty-equals` | Type-safe fixture comparisons |