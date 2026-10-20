"""Diff declared grants (config/access.yaml) against grants actually held in Snowflake.

Managed roles (access, functional, service) are fully declarative: any privilege they
hold that the config does not declare is drift and is revoked. Roles that look managed
(AR_/FR_/SVC_ prefix) but are not in the config are reported, never touched.

Both sides are normalised to object-level atoms so the diff is an exact set difference:
`ALL TABLES IN SCHEMA` is expanded against the tables that exist today, `FUTURE` grants
stay schema-level.
"""
import argparse
import re
import sys
from typing import NamedTuple

from mdp.config import IDENT, load
from mdp.sqlgen import SECURITYADMIN, SYSADMIN, desired_grants, managed_roles

MANAGED_PREFIXES = ("AR_", "FR_", "SVC_")
IGNORED_PRIVS = {"OWNERSHIP"}  # managed roles own nothing; ownership can't be revoked, only transferred


class Atom(NamedTuple):
    grantee: str
    priv: str
    kind: str    # DATABASE SCHEMA TABLE VIEW WAREHOUSE ROLE FUTURE_TABLE FUTURE_VIEW ACCOUNT ...
    target: str  # dotted name; for FUTURE_* the containing schema/database


def _parts(name):
    return [p.strip('"') for p in re.findall(r'"[^"]*"|[^.]+', name)]


def _fqn(name):
    return ".".join(p if IDENT.match(p) else '"' + p + '"' for p in _parts(name))


def _scope_to_atoms(g, inventory):
    """Expand one declared Grant into atoms. inventory: {('TABLE'|'VIEW', 'DB.SCHEMA'): [fqn, ...]}."""
    scope = g.scope
    if scope.startswith("ROLE "):
        return [Atom(g.grantee, "USAGE", "ROLE", scope[5:])]
    m = re.fullmatch(r"(ALL|FUTURE) (TABLES|VIEWS) IN SCHEMA (\S+)", scope)
    if m:
        mode, plural, schema = m.groups()
        kind = plural[:-1]
        if mode == "FUTURE":
            return [Atom(g.grantee, p, f"FUTURE_{kind}", schema) for p in g.privs]
        return [Atom(g.grantee, p, kind, fqn) for fqn in inventory.get((kind, schema), []) for p in g.privs]
    kind, target = scope.split(" ", 1)
    return [Atom(g.grantee, p, kind, target) for p in g.privs]


def desired_atoms(cfg, inventory):
    return {a for g in desired_grants(cfg) for a in _scope_to_atoms(g, inventory)}


def diff(desired, actual):
    return sorted(desired - actual), sorted(actual - desired)


def statement(verb, a):
    """verb is GRANT or REVOKE."""
    prep = "TO" if verb == "GRANT" else "FROM"
    if a.kind == "ROLE":
        return f"{verb} ROLE {_fqn(a.target)} {prep} ROLE {a.grantee}"
    if a.kind == "DATABASE_ROLE":
        return f"{verb} DATABASE ROLE {_fqn(a.target)} {prep} ROLE {a.grantee}"
    if a.kind.startswith("FUTURE_"):
        container = "SCHEMA" if len(_parts(a.target)) == 2 else "DATABASE"
        return f"{verb} {a.priv} ON FUTURE {a.kind[7:]}S IN {container} {_fqn(a.target)} {prep} ROLE {a.grantee}"
    if a.kind == "ACCOUNT":
        return f"{verb} {a.priv} ON ACCOUNT {prep} ROLE {a.grantee}"
    return f"{verb} {a.priv} ON {a.kind.replace('_', ' ')} {_fqn(a.target)} {prep} ROLE {a.grantee}"


def _rows(cur, sql):
    cur.execute(sql)
    cols = [d[0].lower() for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def read_inventory(cur, databases):
    """Tables and views per schema. Run as SYSADMIN, which owns every managed object."""
    inv = {}
    for db in databases:
        for kind, show in (("TABLE", "TABLES"), ("VIEW", "VIEWS")):
            for r in _rows(cur, f"SHOW {show} IN DATABASE {db}"):
                if r["schema_name"] == "INFORMATION_SCHEMA":
                    continue
                schema = f"{r['database_name']}.{r['schema_name']}"
                inv.setdefault((kind, schema), []).append(f"{schema}.{r['name']}")
    return inv


def read_actual(cur, roles):
    atoms = set()
    for role in roles:
        for r in _rows(cur, f"SHOW GRANTS TO ROLE {role}"):
            if r["privilege"] in IGNORED_PRIVS:
                continue
            kind = r["granted_on"]
            if kind == "ROLE":
                atoms.add(Atom(role, "USAGE", "ROLE", r["name"]))
            else:
                atoms.add(Atom(role, r["privilege"], kind, ".".join(_parts(r["name"]))))
        for r in _rows(cur, f"SHOW FUTURE GRANTS TO ROLE {role}"):
            kind = f"FUTURE_{r['grant_on']}"
            atoms.add(Atom(role, r["privilege"], kind, ".".join(_parts(r["name"])[:-1])))
    return atoms


def orphan_roles(cur, managed):
    return sorted(r["name"] for r in _rows(cur, "SHOW ROLES")
                  if r["name"].startswith(MANAGED_PREFIXES) and r["name"] not in set(managed))


def plan(cfg, conn):
    cur = conn.cursor()
    cur.execute(f"USE ROLE {SYSADMIN}")
    inventory = read_inventory(cur, cfg["databases"])
    cur.execute(f"USE ROLE {SECURITYADMIN}")
    roles = managed_roles(cfg)
    existing = {r["name"] for r in _rows(cur, "SHOW ROLES")}
    missing_roles = [r for r in roles if r not in existing]
    actual = read_actual(cur, [r for r in roles if r in existing])
    to_add, to_revoke = diff(desired_atoms(cfg, inventory), actual)
    return to_add, to_revoke, orphan_roles(cur, roles), missing_roles


def main():
    ap = argparse.ArgumentParser(description="Reconcile Snowflake grants with access.yaml")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true", help="show the diff, change nothing (default)")
    mode.add_argument("--apply", action="store_true", help="execute the plan: grant missing, revoke drift")
    ap.add_argument("--fail-on-drift", action="store_true", help="exit 2 if the plan is not empty (for CI)")
    ap.add_argument("--config")
    args = ap.parse_args()

    from mdp.conn import connect
    cfg = load(args.config)
    with connect(role=SECURITYADMIN) as conn:
        to_add, to_revoke, orphans, missing_roles = plan(cfg, conn)
        if missing_roles:
            print(f"! {len(missing_roles)} declared roles do not exist; run `python -m mdp.apply` first: "
                  f"{', '.join(missing_roles[:5])}{'...' if len(missing_roles) > 5 else ''}")
            sys.exit(1)
        for a in to_add:
            print(f"+ {statement('GRANT', a)};")
        for a in to_revoke:
            print(f"- {statement('REVOKE', a)};")
        for r in orphans:
            print(f"? orphan role {r}: looks managed but is not in access.yaml (not touched)")
        print(f"-- plan: {len(to_add)} to grant, {len(to_revoke)} to revoke, {len(orphans)} orphan roles")
        if args.apply and (to_add or to_revoke):
            cur = conn.cursor()
            cur.execute(f"USE ROLE {SECURITYADMIN}")
            for a in to_add:
                cur.execute(statement("GRANT", a))
            for a in to_revoke:
                cur.execute(statement("REVOKE", a))
            print(f"-- applied {len(to_add) + len(to_revoke)} changes")
        elif (to_add or to_revoke) and args.fail_on_drift:
            sys.exit(2)


if __name__ == "__main__":
    main()
