"""Project-level pytest configuration."""

import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "live: marks tests that require real network access (deselect with -m 'not live')",
    )
