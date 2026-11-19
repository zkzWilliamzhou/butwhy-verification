"""Typed errors for butwhy. Every error maps to exactly one locked exit code."""
from __future__ import annotations


class ButwhyError(Exception):
    """Base class. CLI maps subclasses to the closed exit-code set."""
    exit_code = 1


class UsageError(ButwhyError):
    exit_code = 1


class VerifyInvalid(ButwhyError):
    exit_code = 2


class SafetyDenied(ButwhyError):
    exit_code = 3


class ResourceLimit(ButwhyError):
    exit_code = 4


class SchemaError(ButwhyError):
    exit_code = 5


class ReplayError(ButwhyError):
    exit_code = 6


EXIT_CODES = {
    0: "OK",
    1: "usage/general/report error",
    2: "verify invalid or incomplete",
    3: "safety policy denied",
    4: "resource limit exceeded",
    5: "unsupported schema/version",
    6: "capture or replay error",
}
