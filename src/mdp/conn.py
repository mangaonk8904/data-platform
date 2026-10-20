import os
from pathlib import Path

import snowflake.connector
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]


def connect(**overrides):
    load_dotenv(ROOT / ".env")
    key_path = ROOT / os.environ.get("SNOWFLAKE_PRIVATE_KEY_PATH", "keys/rsa_key.p8")
    pk = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    der = pk.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    params = dict(
        account=os.environ["SNOWFLAKE_ACCOUNT"].strip(),
        user=os.environ["SNOWFLAKE_USER"].strip(),
        private_key=der,
        role=os.environ.get("SNOWFLAKE_ROLE", "ACCOUNTADMIN").strip(),
        warehouse=os.environ.get("SNOWFLAKE_WAREHOUSE", "COMPUTE_WH").strip(),
    )
    params.update(overrides)
    return snowflake.connector.connect(**params)
