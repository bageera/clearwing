"""Beacon template injection guard: c2_server must be repr'd into the source."""

import ast

import pytest

from nightwing.exploitation.payloads.authorization import AuthorizationGate
from nightwing.exploitation.payloads.beacon import BeaconGenerator


@pytest.fixture(autouse=True)
def _authorized():
    AuthorizationGate.authorize("c2_beacon_generation")
    yield
    AuthorizationGate.revoke()


class TestBeaconTemplateInjection:
    def test_c2_with_quotes_does_not_break_source(self):
        evil = 'evil"; import os; os.system("touch /tmp/pwned"); "'
        src = BeaconGenerator.generate_sleep_beacon(evil)
        # The generated payload must parse as Python and keep the C2 as data
        ast.parse(src)
        tree = ast.parse(src)
        c2_assign = next(
            n for n in ast.walk(tree)
            if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "C2"
        )
        assert isinstance(c2_assign.value, ast.Constant)
        assert c2_assign.value.value == evil  # the string, quoted

    def test_newline_injection_blocked(self):
        evil = 'x"\nos.system("id")\ny="'
        src = BeaconGenerator.generate_sleep_beacon(evil)
        tree = ast.parse(src)  # must parse despite injected quotes/newlines
        # the injected os.system call must appear only as string DATA, never as
        # an executable ast.Call
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
        assert not any(
            isinstance(c.func, ast.Attribute) and c.func.attr == "system" and
            isinstance(c.func.value, ast.Name) and c.func.value.id == "os"
            for c in calls
        )

    def test_numeric_args_forced_int(self):
        src = BeaconGenerator.generate_sleep_beacon("http://c2", jitter_percent=30)
        assert "JITTER = 30 / 100.0" in src