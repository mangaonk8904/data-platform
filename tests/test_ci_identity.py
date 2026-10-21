import base64
import copy

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mdp import conn
from mdp.ci_identity import public_key_body, statements
from mdp.config import ConfigError, load, validate


@pytest.fixture
def cfg():
    return load()


@pytest.fixture
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, pub.decode()


def test_public_key_body_strips_pem_armour(keypair):
    body = public_key_body(keypair[1])
    assert "BEGIN" not in body and "\n" not in body and base64.b64decode(body)


def test_public_key_body_rejects_private_keys_and_garbage(keypair):
    for bad in (keypair[0].decode(), "hello", ""):
        with pytest.raises(ValueError):
            public_key_body(bad)


def test_ci_user_statements_are_least_privilege(cfg, keypair):
    stmts = statements(cfg, public_key_body(keypair[1]))
    assert {role for role, _ in stmts} == {"SECURITYADMIN"}
    sql = " ".join(s for _, s in stmts)
    assert "ACCOUNTADMIN" not in sql and "DEFAULT_SECONDARY_ROLES = ()" in sql
    assert "GRANT ROLE SYSADMIN TO USER CI_DEPLOYER" in sql and "GRANT ROLE SECURITYADMIN TO USER CI_DEPLOYER" in sql
    assert "managed-by=hr-sync" not in sql      # hr_sync must never manage this user


def test_ci_user_validation(cfg):
    for mutate in (lambda c: c["ci_user"]["roles"].append("ACCOUNTADMIN"),
                   lambda c: c["ci_user"].update(name="PLATFORM_ADMIN"),
                   lambda c: c["ci_user"].update(default_warehouse="WH_NOPE")):
        bad = copy.deepcopy(cfg)
        mutate(bad)
        with pytest.raises(ConfigError):
            validate(bad)


def test_connect_reads_key_from_environment_without_a_file(monkeypatch, tmp_path, keypair):
    seen = {}
    monkeypatch.setattr(conn.snowflake.connector, "connect", lambda **kw: seen.update(kw) or "conn")
    monkeypatch.setattr(conn, "ROOT", tmp_path)          # no keys/ dir, no .env here
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "org-acct")
    monkeypatch.setenv("SNOWFLAKE_USER", "CI_DEPLOYER")
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_B64", base64.b64encode(keypair[0]).decode())
    assert conn.connect() == "conn"
    assert seen["user"] == "CI_DEPLOYER" and isinstance(seen["private_key"], bytes)


def test_prod_guard(monkeypatch):
    monkeypatch.setenv("SNOWFLAKE_ENV", "prod")
    with pytest.raises(SystemExit):
        conn.require_not_prod("seed")
    monkeypatch.setenv("SNOWFLAKE_ENV", "")
    conn.require_not_prod("seed")


def test_seed_refuses_in_prod(monkeypatch):
    from mdp import seed
    monkeypatch.setenv("SNOWFLAKE_ENV", "prod")
    with pytest.raises(SystemExit):
        seed.main()
