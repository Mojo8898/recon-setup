"""Smoke tests for the recon_setup package."""
import pytest


def test_main_importable():
    """recon_setup.main can be imported without errors."""
    import recon_setup.main  # noqa: F401


def test_main_function_exists():
    """recon_setup.main exposes a callable main() function."""
    from recon_setup.main import main
    assert callable(main)
