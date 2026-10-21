import base64
import os
from pathlib import Path

import snowflake.connector
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]


def _private_key_der():
    """Key from SNOWFLAKE_PRIVATE_KEY_B64 (CI: no key file on the runner), else the key file."""
    b64 = os.environ.get("SNOWFLAKE_PRIVATE_KEY_B64", "").strip()
    if b64:
        pem = base64.b64decode(b64)
    else:
        pem = (ROOT / os.environ.get("SNOWFLAKE_PRIVATE_KEY_PATH", "keys/rsa_key.p8")).read_bytes()
    pk = serialization.load_pem_private_key(pem, password=None)
    return pk.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def current_user():
    """The Snowflake user running this tooling (scripts grant roles to it temporarily)."""
    load_dotenv(ROOT / ".env")
    return os.environ["SNOWFLAKE_USER"].strip().upper()


def require_not_prod(what):
    """Destructive demo/seed tooling refuses to run where SNOWFLAKE_ENV=prod (every CI job sets it)."""
    load_dotenv(ROOT / ".env")
    if os.environ.get("SNOWFLAKE_ENV", "").strip().lower() == "prod":
        raise SystemExit(f"refusing to run {what}: SNOWFLAKE_ENV=prod")


def connect(**overrides):
    load_dotenv(ROOT / ".env")
    params = dict(
        account=os.environ["SNOWFLAKE_ACCOUNT"].strip(),
        user=os.environ["SNOWFLAKE_USER"].strip(),
        private_key=_private_key_der(),
        role=os.environ.get("SNOWFLAKE_ROLE", "SYSADMIN").strip(),
        warehouse=os.environ.get("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH").strip(),
    )
    params.update(overrides)
    return snowflake.connector.connect(**params)
