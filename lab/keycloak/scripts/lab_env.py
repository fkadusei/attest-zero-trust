"""Lab credentials, generated rather than hardcoded.

WHY THIS EXISTS

The lab had a hardcoded admin password — literally the same string — in twenty-odd
files. It is not a secret: it belongs to a Keycloak container that lives for the
duration of a test run on localhost and is then torn down. SECURITY.md says so, and
still does.

But a literal password in a public repository is a literal password in a public
repository. GitHub's secret scanning flags it, correctly — its job is to find
`password: "..."`, and that is what this was. A scanner that ignored it because the
value contains the word "not-a-secret" would be a worse scanner.

So the value is gone. It is generated once, written to `lab/.env`, and read from
there by everything that needs it. That file is gitignored. The result:

  * no credential-shaped literal anywhere in the repository
  * a credential that is unique per checkout, which is what it should have been
  * the scanner has nothing to flag, so its output stays worth reading

WHAT THIS IS NOT

This is not a claim that the lab is now secure. The credential still travels over
plain HTTP on loopback, is still shared by every process in the lab, and is still
not worth protecting. It is now merely *generated* rather than *published* — which
is a hygiene fix, not a security one. Saying otherwise would be the kind of
overstatement this project exists to avoid.

CONFIGURATION STILL WINS

An environment variable, if set, takes precedence over the file. That is what lets
CI supply its own value and what lets an operator override without editing
anything.
"""
from __future__ import annotations

import os
import secrets
import pathlib

# lab/keycloak/scripts/lab_env.py -> lab/
LAB_DIR = pathlib.Path(__file__).resolve().parents[2]
ENV_FILE = LAB_DIR / ".env"
EXAMPLE_FILE = LAB_DIR / ".env.example"

# The variables the lab needs. A fresh value is generated for each on first use.
VARIABLES = {
    "LAB_KEYCLOAK_ADMIN_PASSWORD": 24,
    "LAB_POSTGRES_PASSWORD": 24,
    "LAB_APP_DB_APP_PASSWORD": 24,
}

EXAMPLE_TEXT = """# Lab credentials — generated, not committed.
#
# `lab/.env` is created with random values the first time any lab script runs, and
# is gitignored. Copy this file to `.env` only if you want to pin specific values.
#
# Nothing here protects anything: these are credentials for throwaway containers on
# localhost. They are generated so that no credential-shaped literal lives in the
# repository, not because they are worth keeping.
"""


def _generate() -> dict[str, str]:
    return {name: secrets.token_urlsafe(length) for name, length in VARIABLES.items()}


def ensure_env_file() -> dict[str, str]:
    """Return the lab credentials, creating `lab/.env` if it does not exist."""
    values: dict[str, str] = {}

    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()

    # Any variable missing from the file — a checkout from before this existed, or a
    # hand-edited file — is generated and appended rather than left absent. An absent
    # credential would surface as an authentication failure deep inside a test, which
    # is a far worse way to learn about it.
    missing = {k: v for k, v in _generate().items() if k not in values or values[k] == ""}
    if missing:
        values.update(missing)
        LAB_DIR.mkdir(parents=True, exist_ok=True)
        with ENV_FILE.open("a") as handle:
            if ENV_FILE.stat().st_size == 0:
                handle.write(EXAMPLE_TEXT)
            for key, value in missing.items():
                handle.write(f"{key}={value}\n")
        try:
            ENV_FILE.chmod(0o600)
        except OSError:
            pass

    if not EXAMPLE_FILE.exists():
        EXAMPLE_FILE.write_text(
            EXAMPLE_TEXT
            + "\n"
            + "".join(f"# {name}=\n" for name in VARIABLES)
        )

    return values


_CREDENTIALS: dict[str, str] | None = None


def credential(name: str) -> str:
    """One lab credential, from the environment first and the generated file second."""
    global _CREDENTIALS
    from_env = os.environ.get(name)
    if from_env:
        return from_env
    if _CREDENTIALS is None:
        _CREDENTIALS = ensure_env_file()
    return _CREDENTIALS[name]


# Convenience accessors. Importing a name is clearer at the call site than calling
# `credential("...")` and hoping the string is spelled right.
KEYCLOAK_ADMIN_PASSWORD = credential("LAB_KEYCLOAK_ADMIN_PASSWORD")
POSTGRES_PASSWORD = credential("LAB_POSTGRES_PASSWORD")
APP_DB_OWNER_PASSWORD = credential("LAB_APP_DB_OWNER_PASSWORD")
APP_DB_APP_PASSWORD = credential("LAB_APP_DB_APP_PASSWORD")
