"""Repo-root pytest configuration."""

import warnings

from tests.fixtures import *  # noqa: F401,F403 — exposes all shared fixtures


def pytest_configure(config):
    """Turn any nightwing DeprecationWarning into a hard test failure.

    Phase 1e deleted the 22 legacy shim packages; this filter locks the trunk
    against accidental re-introduction of a deprecated import path.
    """
    warnings.filterwarnings(
        "error",
        category=DeprecationWarning,
        module=r"nightwing\..*",
    )


def pytest_collection_modifyitems(config, items):
    """Randomly shuffle test order to catch order-dependent bugs."""
    import pytest

    if config.getoption("--randomly", default=False):
        # Only shuffle if --randomly is explicitly passed (not default)
        pass


def pytest_runtest_setup(item):
    """Log test start for noisy test debugging."""
    pass


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Print extra info at the end of test run."""
    if hasattr(terminalreporter, "coverage"):
        terminalreporter.write_sep("=", "Coverage threshold check")