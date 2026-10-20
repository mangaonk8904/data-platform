"""Render desired state (config/access.yaml) into ordered, idempotent SQL.

Each statement is tagged with the Snowflake role that must run it, so the
applier never does more than the least-privileged built-in role requires.
"""
from mdp.config import all_schemas, expand

SYSADMIN, SECURITYADMIN, ACCOUNTADMIN = "SYSADMIN", "SECURITYADMIN", "ACCOUNTADMIN"


def ar_schema(db, schema, mode):
    return f"AR_{db}__{schema}__{mode}"


def ar_wh(wh):
    return f"AR_{wh}__USAGE"


def _q(s):
    return s.replace("'", "''")


def objects(cfg):
    """Create databases, schemas (managed access) and warehouses. Owned by SYSADMIN."""
    out = []
    for db, d in cfg["databases"].items():
        out.append((SYSADMIN, f"CREATE DATABASE IF NOT EXISTS {db} COMMENT = '{_q(d['comment'])}'"))
        # Snowflake auto-creates an ungoverned PUBLIC schema in every database
        out.append((SYSADMIN, f"DROP SCHEMA IF EXISTS {db}.PUBLIC"))
        for s, m in d["schemas"].items():
            comment = f"owner={m['owner_team']}; sensitivity={m['sensitivity']}"
            out.append((SYSADMIN, f"CREATE SCHEMA IF NOT EXISTS {db}.{s} WITH MANAGED ACCESS COMMENT = '{comment}'"))
            out.append((SYSADMIN, f"ALTER SCHEMA {db}.{s} SET COMMENT = '{comment}'"))
    for wh, w in cfg["warehouses"].items():
        out.append((SYSADMIN,
            f"CREATE WAREHOUSE IF NOT EXISTS {wh} WAREHOUSE_SIZE = {w['size']} "
            f"AUTO_SUSPEND = {w['auto_suspend']} AUTO_RESUME = TRUE INITIALLY_SUSPENDED = TRUE "
            f"COMMENT = '{_q(w['purpose'])}'"))
        out.append((SYSADMIN,
            f"ALTER WAREHOUSE {wh} SET WAREHOUSE_SIZE = {w['size']} AUTO_SUSPEND = {w['auto_suspend']} "
            f"AUTO_RESUME = TRUE"))
    return out


def monitors(cfg):
    """One monthly resource monitor per warehouse: notify at 80%, suspend at 100%."""
    out = []
    for wh, w in cfg["warehouses"].items():
        rm = f"RM_{wh}"
        out.append((ACCOUNTADMIN,
            f"CREATE RESOURCE MONITOR IF NOT EXISTS {rm} WITH CREDIT_QUOTA = {w['credit_quota']} "
            f"FREQUENCY = MONTHLY START_TIMESTAMP = IMMEDIATELY "
            f"TRIGGERS ON 80 PERCENT DO NOTIFY ON 100 PERCENT DO SUSPEND"))
        out.append((ACCOUNTADMIN, f"ALTER RESOURCE MONITOR {rm} SET CREDIT_QUOTA = {w['credit_quota']}"))
        out.append((ACCOUNTADMIN, f"ALTER WAREHOUSE {wh} SET RESOURCE_MONITOR = {rm}"))
    return out


def access_roles(cfg):
    """Create access roles and give them the only privileges in the system."""
    out = []
    for db, s in all_schemas(cfg):
        ro, rw = ar_schema(db, s, "RO"), ar_schema(db, s, "RW")
        out += [(SECURITYADMIN, f"CREATE ROLE IF NOT EXISTS {r}") for r in (ro, rw)]
        sc = f"{db}.{s}"
        out += [(SECURITYADMIN, q) for q in (
            f"GRANT USAGE ON DATABASE {db} TO ROLE {ro}",
            f"GRANT USAGE ON SCHEMA {sc} TO ROLE {ro}",
            f"GRANT SELECT ON ALL TABLES IN SCHEMA {sc} TO ROLE {ro}",
            f"GRANT SELECT ON FUTURE TABLES IN SCHEMA {sc} TO ROLE {ro}",
            f"GRANT SELECT ON ALL VIEWS IN SCHEMA {sc} TO ROLE {ro}",
            f"GRANT SELECT ON FUTURE VIEWS IN SCHEMA {sc} TO ROLE {ro}",
            f"GRANT ROLE {ro} TO ROLE {rw}",
            f"GRANT INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA {sc} TO ROLE {rw}",
            f"GRANT INSERT, UPDATE, DELETE, TRUNCATE ON FUTURE TABLES IN SCHEMA {sc} TO ROLE {rw}",
            f"GRANT CREATE TABLE, CREATE VIEW ON SCHEMA {sc} TO ROLE {rw}",
        )]
    for wh in cfg["warehouses"]:
        r = ar_wh(wh)
        out.append((SECURITYADMIN, f"CREATE ROLE IF NOT EXISTS {r}"))
        out.append((SECURITYADMIN, f"GRANT USAGE ON WAREHOUSE {wh} TO ROLE {r}"))
    return out


def composite_roles(cfg):
    """Functional and service roles hold access roles, never object privileges."""
    out = []
    for name, r in {**cfg["functional_roles"], **cfg["service_roles"]}.items():
        out.append((SECURITYADMIN, f"CREATE ROLE IF NOT EXISTS {name} COMMENT = '{_q(r['comment'])}'"))
        for db, s in expand(cfg, r.get("read", [])):
            out.append((SECURITYADMIN, f"GRANT ROLE {ar_schema(db, s, 'RO')} TO ROLE {name}"))
        for db, s in expand(cfg, r.get("write", [])):
            out.append((SECURITYADMIN, f"GRANT ROLE {ar_schema(db, s, 'RW')} TO ROLE {name}"))
        for wh in r.get("warehouses", []):
            out.append((SECURITYADMIN, f"GRANT ROLE {ar_wh(wh)} TO ROLE {name}"))
    return out


def render(cfg):
    return objects(cfg) + monitors(cfg) + access_roles(cfg) + composite_roles(cfg)
