"""One-time: drop the service user from ACCOUNTADMIN to SYSADMIN + SECURITYADMIN.

Safe ordering: grant the new roles and delegate monitor management, PROVE the narrowed
user can still do the one ACCOUNTADMIN-only job (resource monitors), and only then revoke
ACCOUNTADMIN. Any failed proof aborts before the revoke. Default is a dry run.
"""
import argparse
import sys

from mdp.config import load
from mdp.conn import connect
from mdp.sqlgen import ACCOUNTADMIN, monitors, platform_user


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--execute", action="store_true", help="run it (default: print the plan)")
    args = ap.parse_args()
    cfg = load()
    user = cfg["platform_user"]["name"]
    steps = platform_user(cfg)
    revoke = (ACCOUNTADMIN, f"REVOKE ROLE ACCOUNTADMIN FROM USER {user}")
    if not args.execute:
        for role, sql in steps + [revoke]:
            print(f"[{role}] {sql};")
        print("-- dry run; pass --execute (as a user holding ACCOUNTADMIN) to apply")
        return

    with connect(role=ACCOUNTADMIN) as conn:
        cur = conn.cursor()
        for role, sql in steps:
            cur.execute(f"USE ROLE {role}")
            cur.execute(sql)
        # proof: full tooling path as the narrowed roles, ACCOUNTADMIN powers disabled
        cur.execute("USE SECONDARY ROLES NONE")
        try:
            for role, sql in monitors(cfg):
                cur.execute(f"USE ROLE {role}")
                cur.execute(sql)
        except Exception as e:
            print(f"ABORT before revoke: narrowed roles cannot manage monitors: {e}")
            sys.exit(1)
        cur.execute("USE SECONDARY ROLES ALL")
        cur.execute(f"USE ROLE {ACCOUNTADMIN}")
        cur.execute(revoke[1])
        print(f"{user} now holds {cfg['platform_user']['roles']} only")


if __name__ == "__main__":
    main()
