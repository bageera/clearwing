#!/usr/bin/env python3
"""Test script to verify OSINT improvements functionality."""

import importlib.util


def test_imports():
    """Test that all new modules can be imported successfully."""
    modules = [
        "clearwing.data.database.recon_store",
        "clearwing.workflows.osint_workflow",
        "clearwing.utils.output_parsers",
        "clearwing.intel.correlation",
        "clearwing.native.shodan_tools",
    ]
    for mod in modules:
        assert importlib.util.find_spec(mod) is not None, f"Module not found: {mod}"


def test_recon_store_classes():
    """Verify recon_store exposes expected classes."""
    from clearwing.data.database.recon_store import ReconResult, ReconStore

    assert ReconResult is not None
    assert ReconStore is not None


def test_osint_workflow_function():
    """Verify osint_workflow exposes expected function."""
    from clearwing.workflows.osint_workflow import run_passive_subdomain_recon

    assert callable(run_passive_subdomain_recon)


def test_output_parsers_functions():
    """Verify output_parsers exposes expected functions."""
    from clearwing.utils.output_parsers import parse_github_json, parse_wayback_json

    assert callable(parse_github_json)
    assert callable(parse_wayback_json)


def test_correlation_classes():
    """Verify correlation module exposes expected classes/functions."""
    from clearwing.intel.correlation import IntelCorrelator, correlate_osint_findings

    assert IntelCorrelator is not None
    assert callable(correlate_osint_findings)


def test_shodan_tools_functions():
    """Verify shodan_tools exposes expected functions."""
    from clearwing.native.shodan_tools import parse_shodan_results, query_shodan

    assert callable(parse_shodan_results)
    assert callable(query_shodan)
