"""Secret classification and environment transplant policy.

Design choice (hardening, documented): we NEVER emit a digest derived from a
secret value. A stable digest of a low-entropy secret is brute-forceable and
would leak the secret across runs. Instead sensitive values are replaced with a
length BUCKET and a category label. Capsules therefore contain no secret
material and no value-derived hashes, while remaining fully deterministic.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Optional

# Exact names that must never be transplanted into a child environment.
NEVER_EXACT = frozenset(
    {
        "HOME", "USER", "LOGNAME", "SHELL", "PATH", "PATHEXT", "COMSPEC",
        "TMPDIR", "TEMP", "TMP", "PWD", "OLDPWD", "IFS", "BASH_ENV", "ENV",
        "PROMPT_COMMAND", "SHELLOPTS", "GLOBIGNORE", "CDPATH", "LD_PRELOAD",
        "LD_LIBRARY_PATH", "LD_AUDIT", "PYTHONPATH", "PYTHONHOME",
        "PYTHONSTARTUP", "PYTHONNOUSERSITE", "NODE_OPTIONS", "NODE_PATH",
        "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS",
        "MAVEN_OPTS", "ANT_OPTS", "GRADLE_OPTS", "PERL5LIB", "PERL5OPT",
        "RUBYLIB", "RUBYOPT", "GIT_EXEC_PATH", "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM", "KUBECONFIG", "HTTP_PROXY", "HTTPS_PROXY",
        "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR",
    }
)

# Prefixes that must never be transplanted.
NEVER_PREFIXES = (
    "LD_", "DYLD_", "PYTHON", "NODE_", "DENO_", "JAVA_", "JDK_", "AWS_",
    "AZURE_", "GOOGLE_", "GCP_", "GITHUB_", "GITLAB_", "SSH_", "GIT_",
    "NPM_CONFIG_", "CARGO_", "DOCKER_", "KUBE_", "TWINE_", "PYPI_",
)

# Host-specific values that are meaningless or misleading when replayed.
HOST_BOUND = frozenset(
    {"HOSTNAME", "HOSTTYPE", "MACHTYPE", "OSTYPE", "VENDOR", "SHLVL", "_",
     "SSH_TTY", "SSH_CONNECTION", "SSH_CLIENT", "DISPLAY", "XAUTHORITY",
     "SESSION_MANAGER", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR",
     "XDG_SESSION_ID", "PWD", "OLDPWD", "COLUMNS", "LINES"}
)

# Names whose VALUES are sensitive even though the name is otherwise safe.
SENSITIVE_NAME_RE = re.compile(
    r"(SECRET|TOKEN|PASSWORD|PASSWD|APIKEY|API_KEY|PRIVATE_KEY|CREDENTIAL|"
    r"AUTH|SESSION|COOKIE|ACCESS_KEY|SIGNING|CERT|DATABASE_URL|REDIS_URL|"
    r"MONGODB_URI|AMQP_URL|BEARER)",
    re.IGNORECASE,
)

SAFE_LOCALES = frozenset({"C", "C.UTF-8", "POSIX", "en_US.UTF-8", "en_US.utf8"})
SAFE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
SAFE_LOCALE_RE = re.compile(r"^[A-Za-z0-9_@.=+-]{1,64}$")
SAFE_TZ_RE = re.compile(r"^[A-Za-z0-9_+\-/.:]{1,64}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

REDACT_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}"
    r"|gh[pousr]_[0-9A-Za-z]{36}"
    r"|glpat-[0-9A-Za-z_\-]{20}"
    r"|xox[baprs]-[0-9A-Za-z\-]{10,}"
    r"|[Aa]uthorization:\s*[Bb]earer\s+[A-Za-z0-9._\-]+"
    r"|(?:password|passwd|token|secret|api[_-]?key)\s*[=:]\s*[^\s&;,'\"]+"
    r"|[A-Za-z0-9+/]{40,}={0,2})",
)

ALLOWLIST = frozenset(
    {
        "LANG", "LC_ALL", "LC_CTYPE", "LC_COLLATE", "LC_TIME", "LC_NUMERIC",
        "TZ", "TERM", "PYTHONDONTWRITEBYTECODE", "SOURCE_DATE_EPOCH",
        "BUTWHY_REPEAT_INDEX", "BUTWHY_LINE_ENDING",
    }
)


def never_transplant(name: str) -> bool:
    """True when an env name must never be set or transplanted by a factor."""
    # NFKC first: fullwidth/compatibility confusables (e.g. ＰＹＴＨＯＮＰＡＴＨ)
    # must not slip past the denylist by looking like a different string.
    upper = unicodedata.normalize("NFKC", name).upper()
    if upper in NEVER_EXACT or upper in HOST_BOUND:
        return True
    if any(upper.startswith(prefix) for prefix in NEVER_PREFIXES):
        return True
    if SENSITIVE_NAME_RE.search(upper):
        return True
    return False


def is_sensitive(name: str) -> bool:
    """True when a value must never appear in a capsule, ledger or report."""
    return never_transplant(name) or bool(SENSITIVE_NAME_RE.search(name.upper()))


def safe_value(name: str, value: str) -> bool:
    """Validate a value that a factor wants to place in the child environment."""
    if not SAFE_NAME_RE.match(name):
        return False
    if never_transplant(name):
        return False
    if not isinstance(value, str) or len(value) > 512:
        return False
    if CONTROL_RE.search(value):
        return False
    upper = name.upper()
    if upper in {"LANG", "LC_ALL", "LC_CTYPE", "LC_COLLATE", "LC_TIME"}:
        return bool(SAFE_LOCALE_RE.match(value)) and value in SAFE_LOCALES
    if upper == "TZ":
        return bool(SAFE_TZ_RE.match(value)) and ".." not in value
    if "/" in value or "\\" in value or "~" in value:
        return False
    return True


HEX_TOKEN_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
OPAQUE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{16,}$")


def looks_like_token(value: str) -> bool:
    """Value-class detection: secrets are often named innocuously.

    Host-specific identifiers (client ids, pod ids, sandbox user ids) are not
    caught by a name denylist, so we also refuse to store any opaque,
    high-entropy-looking value in plaintext.
    """
    if not value:
        return False
    if REDACT_RE.search(value):
        return True
    if HEX_TOKEN_RE.match(value):
        return True
    # Long opaque identifiers are host-specific even when they contain no
    # digits (e.g. "yuanbao-one-agent-yuanbao-open-api"). Require length >= 20
    # so ordinary short factor values ("on", "UTC", "C.UTF-8") stay plain.
    if OPAQUE_TOKEN_RE.match(value) and len(value) >= 20:
        return True
    if "://" in value and "@" in value:
        return True
    return False


def length_bucket(length: int) -> str:
    for hi in (8, 16, 32, 64, 128, 256, 512, 1024):
        if length <= hi:
            return "0-%d" % hi
    return "1024+"


def mask(value: Optional[str]) -> str:
    """Deterministic, value-free redaction marker. No digest of the secret."""
    if value is None:
        return "[REDACTED:none]"
    return "[REDACTED:secret:len=%s]" % length_bucket(len(value))


def redact_text(text: str) -> str:
    """Redact token-shaped substrings from captured output before storage."""
    return REDACT_RE.sub("[REDACTED]", text)


def env_record(name: str, value: Optional[str]) -> dict:
    """Build a capsule env entry. Never stores a sensitive value."""
    if value is None:
        return {
            "name": name,
            "value": None,
            "state": "absent",
            "transplantable": False,
            "redacted": is_sensitive(name),
        }
    sensitive = is_sensitive(name)
    # Only values that pass the factor value policy are stored in plain text.
    # Everything else is reduced to a coarse length bucket, never a digest of
    # the secret (a stable digest of a low-entropy secret is brute-forceable).
    plain = (not sensitive) and safe_value(name, value) and not looks_like_token(value)
    return {
        "name": name,
        "value": value if plain else None,
        "state": "present",
        "transplantable": bool(plain),
        "redacted": not plain,
        "length_bucket": length_bucket(len(value)),
    }
