"""Tag-driven masking and row access policies (Phase 3).

One tag (governance.tag) is put on columns; one masking policy per data type is attached
to the tag, and the policy body decides per tag value who sees real data. So protecting a
column is a single tagging step. Row access policies are per table (Snowflake has no
tag-based row policies) and read a role->region entitlements table that is synced from config.

`definitions` is idempotent DDL (tag, policies, entitlements). `plan` diffs *attachments*
(tag on column, policy on tag, row policy on table) against live state and also runs
coverage checks: a column in a restricted schema that is not classified, or classified but of
a type no masking policy covers, is a finding because it would silently be readable.
"""
import argparse
import re
import sys
from typing import NamedTuple

from mdp.config import column_classes, load
from mdp.sqlgen import ACCOUNTADMIN, SYSADMIN, _q

POLICY_SCHEMA = "GOVERNANCE.POLICIES"
ENTITLEMENTS = "GOVERNANCE.ENTITLEMENTS.REGION_ACCESS"
# family -> (policy argument type, masked value)
APPLY_PRIVS = ("APPLY TAG", "APPLY MASKING POLICY", "APPLY ROW ACCESS POLICY")
FAMILIES = {"STRING": ("VARCHAR", "'***MASKED***'"), "NUMBER": ("NUMBER", "NULL"), "DATE": ("DATE", "NULL")}


class Atom(NamedTuple):
    kind: str    # COLUMN_TAG | TAG_MASK | TABLE_RAP
    target: str  # column fqn | tag fqn | table fqn
    value: str   # tag value | policy fqn | 'policy(column)'


def mask_policy(family):
    return f"{POLICY_SCHEMA}.MASK_{family}"


def rap_policy(table):
    return f"{POLICY_SCHEMA}.RAP_{table.replace('.', '_')}"


def family_of(sql_type):
    t = sql_type.upper()
    if t.startswith(("VARCHAR", "TEXT", "STRING", "CHAR")):
        return "STRING"
    if t.startswith(("NUMBER", "DECIMAL", "NUMERIC", "INT")):
        return "NUMBER"
    if t == "DATE":
        return "DATE"
    return None


def _roles(names):
    return " OR ".join(f"IS_ROLE_IN_SESSION('{r}')" for r in names)


def mask_body(cfg, family):
    tag = cfg["governance"]["tag"]
    cur = f"SYSTEM$GET_TAG_ON_CURRENT_COLUMN('{tag}')"
    arms = []
    for cls, c in cfg["governance"]["classes"].items():
        if c.get("mask", True) and c.get("unmask"):
            arms.append(f"WHEN {cur} = '{cls}' AND ({_roles(c['unmask'])}) THEN val")
    return f"CASE {' '.join(arms)} ELSE {FAMILIES[family][1]} END"


def rap_body(table, ra):
    entitled = (f"EXISTS (SELECT 1 FROM {ENTITLEMENTS} e WHERE e.table_name = '{table}' "
                f"AND IS_ROLE_IN_SESSION(e.role_name) AND e.region = v)")
    return " OR ".join(([_roles(ra["unrestricted"])] if ra.get("unrestricted") else []) + [entitled])


def bootstrap(cfg):
    """One-time break-glass. Only ACCOUNTADMIN can grant account-level APPLY privileges
    (SECURITYADMIN cannot), so a human holding it runs this once, e.g. in Snowsight."""
    return [(ACCOUNTADMIN, f"GRANT {p} ON ACCOUNT TO ROLE {SYSADMIN}") for p in APPLY_PRIVS]


def missing_bootstrap(cur):
    cur.execute(f"SHOW GRANTS TO ROLE {SYSADMIN}")
    cols = [d[0].lower() for d in cur.description]
    held = {r[cols.index("privilege")] for r in cur.fetchall() if r[cols.index("granted_on")] == "ACCOUNT"}
    return [p for p in APPLY_PRIVS if p not in held]


def definitions(cfg):
    """Idempotent DDL. Policies are created once then re-bodied, since CREATE OR REPLACE
    would fail (or detach) while they are attached."""
    g = cfg.get("governance")
    if not g:
        return []
    out = []
    classes = ", ".join(f"'{c}'" for c in g["classes"])
    out.append((SYSADMIN, f"CREATE TAG IF NOT EXISTS {g['tag']} ALLOWED_VALUES {classes} "
                          f"COMMENT = 'Data classification; drives masking policies'"))
    for fam, (arg, _) in FAMILIES.items():
        p = mask_policy(fam)
        out.append((SYSADMIN, f"CREATE MASKING POLICY IF NOT EXISTS {p} AS (val {arg}) RETURNS {arg} -> val"))
        out.append((SYSADMIN, f"ALTER MASKING POLICY {p} SET BODY -> {mask_body(cfg, fam)}"))
    out.append((SYSADMIN, f"CREATE TABLE IF NOT EXISTS {ENTITLEMENTS} "
                          f"(table_name VARCHAR, role_name VARCHAR, region VARCHAR)"))
    out.append((SYSADMIN, f"TRUNCATE TABLE {ENTITLEMENTS}"))
    rows = [(t, r, region) for t, ra in g.get("row_access", {}).items()
            for r, regions in ra.get("regions", {}).items() for region in regions]
    if rows:
        vals = ", ".join(f"('{_q(t)}', '{_q(r)}', '{_q(x)}')" for t, r, x in rows)
        out.append((SYSADMIN, f"INSERT INTO {ENTITLEMENTS} VALUES {vals}"))
    for t, ra in g.get("row_access", {}).items():
        p = rap_policy(t)
        out.append((SYSADMIN, f"CREATE ROW ACCESS POLICY IF NOT EXISTS {p} AS (v VARCHAR) RETURNS BOOLEAN -> TRUE"))
        out.append((SYSADMIN, f"ALTER ROW ACCESS POLICY {p} SET BODY -> {rap_body(t, ra)}"))
    return out


def desired_atoms(cfg):
    g = cfg["governance"]
    # Classes with mask: false are declared (for coverage) but not tagged: any tag value would
    # attach the masking policy, which also breaks columns used as row-policy arguments.
    atoms = {Atom("COLUMN_TAG", c, cls) for c, cls in column_classes(cfg).items()
             if g["classes"][cls].get("mask", True)}
    atoms |= {Atom("TAG_MASK", g["tag"], mask_policy(f)) for f in FAMILIES}
    atoms |= {Atom("TABLE_RAP", t, f"{rap_policy(t)}({ra['column']})") for t, ra in g.get("row_access", {}).items()}
    return atoms


def statement(verb, a, cfg):
    """verb: ADD or REMOVE."""
    tag = cfg["governance"]["tag"]
    if a.kind == "COLUMN_TAG":
        table, col = a.target.rsplit(".", 1)
        what = f"SET TAG {tag} = '{a.value}'" if verb == "ADD" else f"UNSET TAG {tag}"
        return f"ALTER TABLE {table} MODIFY COLUMN {col} {what}"
    if a.kind == "TAG_MASK":
        return f"ALTER TAG {a.target} {'SET' if verb == 'ADD' else 'UNSET'} MASKING POLICY {a.value}"
    policy, col = a.value[:-1].split("(")
    if verb == "ADD":
        return f"ALTER TABLE {a.target} ADD ROW ACCESS POLICY {policy} ON ({col})"
    return f"ALTER TABLE {a.target} DROP ROW ACCESS POLICY {policy}"


def check_columns(cfg, live):
    """live: {table fqn: {COLUMN: sql type}} for every existing table in scope. Returns findings."""
    g, classes, out = cfg["governance"], column_classes(cfg), []
    for table, cols in live.items():
        configured = g["columns"].get(table)
        if configured is None:
            out.append(f"{table}: table is in a restricted schema but has no classification in governance.columns")
            continue
        for c, t in cols.items():
            cls = classes.get(f"{table}.{c}")
            if cls is None:
                out.append(f"{table}.{c}: unclassified column")
            elif g["classes"][cls].get("mask", True) and family_of(t) is None:
                out.append(f"{table}.{c}: class {cls} but type {t} has no masking policy (would be readable)")
        out += [f"{table}.{c}: classified in config but missing from the table" for c in configured if c not in cols]
    for table in list(g["columns"]) + list(g.get("row_access", {})):
        if table not in live:
            out.append(f"{table}: declared in governance but the table does not exist (run mdp.seed)")
    for t, ra in g.get("row_access", {}).items():
        if t in live and ra["column"] not in live[t]:
            out.append(f"{t}: row_access column {ra['column']} does not exist")
    return sorted(set(out))


def _rows(cur, sql):
    cur.execute(sql)
    cols = [d[0].lower() for d in cur.description]
    return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]


def scope_tables(cfg, cur):
    """Tables we must account for: everything configured plus every table in a restricted schema."""
    g = cfg["governance"]
    tables = set(g["columns"]) | set(g.get("row_access", {}))
    for db, d in cfg["databases"].items():
        restricted = {s for s, m in d["schemas"].items() if m["sensitivity"] == "restricted"}
        for r in _rows(cur, f"SHOW TABLES IN DATABASE {db}"):
            if r["schema_name"] in restricted:
                tables.add(f"{db}.{r['schema_name']}.{r['name']}")
    return sorted(tables)


def read_live(cfg, cur):
    tag = cfg["governance"]["tag"]
    tdb, tschema, tname = tag.split(".")
    live, actual = {}, set()
    for table in scope_tables(cfg, cur):
        try:
            cols = _rows(cur, f"DESC TABLE {table}")
        except Exception:
            continue  # reported as 'table does not exist' by check_columns
        live[table] = {r["name"]: r["type"] for r in cols}
        for r in _rows(cur, f"SELECT * FROM TABLE({tdb}.INFORMATION_SCHEMA.TAG_REFERENCES_ALL_COLUMNS('{table}', 'table'))"):
            if (r["tag_database"], r["tag_schema"], r["tag_name"]) == (tdb, tschema, tname):
                actual.add(Atom("COLUMN_TAG", f"{table}.{r['column_name']}", r["tag_value"]))
        for r in _rows(cur, f"SELECT * FROM TABLE({tdb}.INFORMATION_SCHEMA.POLICY_REFERENCES("
                            f"REF_ENTITY_NAME => '{table}', REF_ENTITY_DOMAIN => 'TABLE'))"):
            if r["policy_kind"] == "ROW_ACCESS_POLICY":
                col = re.findall(r"[A-Za-z0-9_]+", r["ref_arg_column_names"] or "")[0]
                actual.add(Atom("TABLE_RAP", table, f"{r['policy_db']}.{r['policy_schema']}.{r['policy_name']}({col})"))
    for r in _rows(cur, f"SELECT * FROM TABLE({tdb}.INFORMATION_SCHEMA.POLICY_REFERENCES("
                        f"REF_ENTITY_NAME => '{tag}', REF_ENTITY_DOMAIN => 'TAG'))"):
        actual.add(Atom("TAG_MASK", tag, f"{r['policy_db']}.{r['policy_schema']}.{r['policy_name']}"))
    return live, actual


def diff(desired, actual):
    return sorted(desired - actual), sorted(actual - desired)


def plan(cfg, cur):
    live, actual = read_live(cfg, cur)
    to_add, to_remove = diff(desired_atoms(cfg), actual)
    return check_columns(cfg, live), to_add, to_remove


def main():
    ap = argparse.ArgumentParser(description="Apply and reconcile tag-based masking and row access policies")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true", help="show findings and attachment diff (default)")
    mode.add_argument("--apply", action="store_true", help="create policies, sync entitlements, attach/detach")
    ap.add_argument("--dry-run", action="store_true", help="print the definition SQL, touch nothing")
    ap.add_argument("--bootstrap-sql", action="store_true", help="print the one-time ACCOUNTADMIN grants")
    ap.add_argument("--fail-on-drift", action="store_true", help="exit 1 on findings, 2 on drift (for CI)")
    ap.add_argument("--config")
    args = ap.parse_args()
    cfg = load(args.config)

    if args.bootstrap_sql:
        for role, sql in bootstrap(cfg):
            print(f"[{role}] {sql};")
        return
    if args.dry_run:
        for role, sql in definitions(cfg):
            print(f"[{role}] {sql};")
        return

    from mdp.conn import connect
    with connect(role=SYSADMIN) as conn:
        cur = conn.cursor()
        cur.execute("USE SECONDARY ROLES NONE")
        if args.apply:
            missing = missing_bootstrap(cur)
            if missing:
                print(f"! SYSADMIN lacks {', '.join(missing)}. A human with ACCOUNTADMIN must run once:")
                for _, sql in bootstrap(cfg):
                    print(f"    {sql};")
                sys.exit(1)
            current = None
            for role, sql in definitions(cfg):
                if role != current:
                    cur.execute(f"USE ROLE {role}")
                    current = role
                cur.execute(sql)
            cur.execute(f"USE ROLE {SYSADMIN}")
            print("-- definitions applied (tag, policies, entitlements)")
        findings, to_add, to_remove = plan(cfg, cur)
        for f in findings:
            print(f"! {f}")
        for a in to_remove:
            print(f"- {statement('REMOVE', a, cfg)};")
        for a in to_add:
            print(f"+ {statement('ADD', a, cfg)};")
        print(f"-- plan: {len(to_add)} to add, {len(to_remove)} to remove, {len(findings)} findings")
        if args.apply:
            if findings:
                print("-- not attaching: fix findings first")
                sys.exit(1)
            for a in to_remove:  # removals first so a changed row-policy column is dropped before re-added
                cur.execute(statement("REMOVE", a, cfg))
            for a in to_add:
                cur.execute(statement("ADD", a, cfg))
            print(f"-- applied {len(to_add) + len(to_remove)} changes")
        elif args.fail_on_drift:
            sys.exit(1 if findings else 2 if (to_add or to_remove) else 0)


if __name__ == "__main__":
    main()
