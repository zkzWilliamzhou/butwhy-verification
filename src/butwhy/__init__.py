"""butwhy - counterfactual one-factor replay for 'works on my machine' failures.

Offline, Python 3.10+ standard library only. It never claims root cause.
"""
from __future__ import annotations

from .errors import ButwhyError, SafetyDenied

VERSION = "0.1.0"
SCHEMA_VERSION = 1
GENERATOR = "butwhy"

__all__ = ["ButwhyError", "SafetyDenied", "VERSION", "SCHEMA_VERSION", "GENERATOR"]
