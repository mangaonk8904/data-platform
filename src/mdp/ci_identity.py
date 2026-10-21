"""Create or rotate the Snowflake user that GitHub Actions deploys as (config: ci_user).

Runs as SECURITYADMIN: that role can create users and grant SYSADMIN/SECURITYADMIN, so no
ACCOUNTADMIN is involved, and CI_DEPLOYER ends up with exactly the privileges PLATFORM_ADMIN has.
Idempotent: re-running with a new public key rotates the key. Default is a dry run; the private
key never touches this tool (generate it with openssl, see docs/cicd.md).
"""
import argparse
import re
from pathlib import Path

from mdp.config import load
from mdp.sqlgen import SECURITYADMIN, _q

MARK = "managed-by=platform; purpose=ci-deploy"


def public_key_body(pem):
    """The base64 body of a PEM public key, as ALTER USER ... SET RSA_PUBLIC_KEY expects it."""
    m = re.fullmatch(r"\s*-----BEGIN PUBLIC KEY-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END PUBLIC KEY-----\s*", pem)
    if not m:
        raise ValueError("not a PEM public key (expected -----BEGIN PUBLIC KEY-----)")
    return re.sub(r"\s+", "", m.group(1))


def statements(cfg, key_body, user_type="SERVICE"):
    u = cfg["ci_user"]
    kind = f" TYPE = {user_type}" if user_type else ""
    out = [
        (SECURITYADMIN, f"CREATE USER IF NOT EXISTS {u['name']}{kind} COMMENT = '{_q(MARK)}'"),
        (SECURITYADMIN, f"ALTER USER {u['name']} SET RSA_PUBLIC_KEY = '{key_body}', DEFAULT_ROLE = {u['default_role']}, "
                        f"DEFAULT_WAREHOUSE = {u['default_warehouse']}, DEFAULT_SECONDARY_ROLES = ()"),
    ]
    return out + [(SECURITYADMIN, f"GRANT ROLE {r} TO USER {u['name']}") for r in u["roles"]]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--public-key-file", required=True, help="PEM public key to register")
    ap.add_argument("--user-type", default="SERVICE", help="Snowflake user TYPE; pass '' on accounts without TYPE support")
    ap.add_argument("--apply", action="store_true", help="execute (default: print)")
    ap.add_argument("--config")
    args = ap.parse_args()
    cfg = load(args.config)
    stmts = statements(cfg, public_key_body(Path(args.public_key_file).read_text()), args.user_type)
    if not args.apply:
        for role, sql in stmts:
            print(f"[{role}] {sql[:150]}{'...' if len(sql) > 150 else ''};")
        print("-- dry run; pass --apply to execute")
        return
    from mdp.conn import connect
    with connect(role=SECURITYADMIN) as conn:
        cur = conn.cursor()
        cur.execute("USE SECONDARY ROLES NONE")
        for _, sql in stmts:
            cur.execute(sql)
        cur.execute(f"SHOW GRANTS TO USER {cfg['ci_user']['name']}")
        cols = [d[0].lower() for d in cur.description]
        held = sorted(dict(zip(cols, r, strict=True))["role"] for r in cur.fetchall())
        print(f"{cfg['ci_user']['name']} ready, holds {held}")


if __name__ == "__main__":
    main()
