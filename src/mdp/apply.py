import argparse

from mdp.config import load
from mdp.conn import connect
from mdp.sqlgen import render


def main():
    ap = argparse.ArgumentParser(description="Apply access.yaml (additive; never revokes)")
    ap.add_argument("--dry-run", action="store_true", help="print SQL without executing")
    ap.add_argument("--config")
    args = ap.parse_args()

    stmts = render(load(args.config))
    if args.dry_run:
        for role, sql in stmts:
            print(f"[{role}] {sql};")
        print(f"-- {len(stmts)} statements")
        return

    with connect(role="SECURITYADMIN") as conn:
        cur = conn.cursor()
        current = None
        for role, sql in stmts:
            if role != current:
                cur.execute(f"USE ROLE {role}")
                current = role
            cur.execute(sql)
        print(f"applied {len(stmts)} statements")


if __name__ == "__main__":
    main()
