"""Shared pytest configuration.

Hypothesis profiles: ``default`` (CI-sized) and ``deep`` (long fuzz campaign):
    HYPOTHESIS_PROFILE=deep python -m pytest tests/test_fuzz_properties.py
"""
import os

from hypothesis import HealthCheck, settings

settings.register_profile("default", max_examples=150, deadline=None,
                          suppress_health_check=[HealthCheck.too_slow])
settings.register_profile("deep", max_examples=3000, deadline=None,
                          suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))
os.environ.setdefault("SMS_LOG_LEVEL", "WARNING")
