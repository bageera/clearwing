"""Clearwing — autonomous LLM-driven security testing platform."""

from .core import Config, CoreEngine
from .core.config import ScanConfig

__all__ = ["CoreEngine", "Config", "ScanConfig", "__version__"]
__version__ = "0.1.0"


def main():
    """Main entry point for Clearwing."""
    from .ui.cli import CLI

    cli = CLI()
    cli.run()
