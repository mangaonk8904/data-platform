"""Render desired state (config/access.yaml) into ordered, idempotent SQL.

Each statement is tagged with the Snowflake role that must run it, so the
applier never does more than the least-privileged built-in role requires.
"""
from typing import NamedTuple

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
    """Day-to-day quota changes, as SYSADMIN (which owns the monitors after bootstrap)."""
    out = []
    for wh, w in cfg["warehouses"].items():
        rm = f"RM_{wh}"
        out.append((SYSADMIN, f"ALTER RESOURCE MONITOR {rm} SET CREDIT_QUOTA = {w['credit_quota']}"))
    return out


def monitor_bootstrap(cfg):
    """Only ACCOUNTADMIN can create resource monitors (the privilege is not grantable), so
    create them once, notify at 80% / suspend at 100%, hand ownership to SYSADMIN, and attach
    them to warehouses (that needs MODIFY on the whole ACCOUNT, too broad to delegate)."""
    out = []
    for wh, w in cfg["warehouses"].items():
        rm = f"RM_{wh}"
        out.append((ACCOUNTADMIN,
            f"CREATE RESOURCE MONITOR IF NOT EXISTS {rm} WITH CREDIT_QUOTA = {w['credit_quota']} "
            f"FREQUENCY = MONTHLY START_TIMESTAMP = IMMEDIATELY "
            f"TRIGGERS ON 80 PERCENT DO NOTIFY ON 100 PERCENT DO SUSPEND"))
        out.append((ACCOUNTADMIN, f"GRANT OWNERSHIP ON RESOURCE MONITOR {rm} TO ROLE {SYSADMIN} COPY CURRENT GRANTS"))
        out.append((ACCOUNTADMIN, f"ALTER WAREHOUSE {wh} SET RESOURCE_MONITOR = {rm}"))
    return out


class Grant(NamedTuple):
    """One declared grant. `scope` is the SQL object clause, e.g. 'SCHEMA RAW.X' or
    'ALL TABLES IN SCHEMA RAW.X'; role grants use 'ROLE <name>'."""
    grantee: str
    privs: tuple
    scope: str

    def sql(self):
        if self.scope.startswith("ROLE "):
            return f"GRANT {self.scope} TO ROLE {self.grantee}"
        return f"GRANT {', '.join(self.privs)} ON {self.scope} TO ROLE {self.grantee}"


def access_role_names(cfg):
    names = []
    for db, s in all_schemas(cfg):
        names += [ar_schema(db, s, "RO"), ar_schema(db, s, "RW")]
    return names + [ar_wh(wh) for wh in cfg["warehouses"]]


def access_grants(cfg):
    """The only object privileges in the system: access roles on schemas and warehouses."""
    out = []
    for db, s in all_schemas(cfg):
        ro, rw, sc = ar_schema(db, s, "RO"), ar_schema(db, s, "RW"), f"{db}.{s}"
        out += [
            Grant(ro, ("USAGE",), f"DATABASE {db}"),
            Grant(ro, ("USAGE",), f"SCHEMA {sc}"),
            Grant(ro, ("SELECT",), f"ALL TABLES IN SCHEMA {sc}"),
            Grant(ro, ("SELECT",), f"FUTURE TABLES IN SCHEMA {sc}"),
            Grant(ro, ("SELECT",), f"ALL VIEWS IN SCHEMA {sc}"),
            Grant(ro, ("SELECT",), f"FUTURE VIEWS IN SCHEMA {sc}"),
            Grant(rw, ("USAGE",), f"ROLE {ro}"),
            Grant(rw, ("INSERT", "UPDATE", "DELETE", "TRUNCATE"), f"ALL TABLES IN SCHEMA {sc}"),
            Grant(rw, ("INSERT", "UPDATE", "DELETE", "TRUNCATE"), f"FUTURE TABLES IN SCHEMA {sc}"),
            Grant(rw, ("CREATE TABLE", "CREATE VIEW"), f"SCHEMA {sc}"),
        ]
    out += [Grant(ar_wh(wh), ("USAGE",), f"WAREHOUSE {wh}") for wh in cfg["warehouses"]]
    return out


def composite_grants(cfg):
    """Functional and service roles hold access roles, never object privileges."""
    out = []
    for name, r in {**cfg["functional_roles"], **cfg["service_roles"]}.items():
        out += [Grant(name, ("USAGE",), f"ROLE {ar_schema(db, s, 'RO')}") for db, s in expand(cfg, r.get("read", []))]
        out += [Grant(name, ("USAGE",), f"ROLE {ar_schema(db, s, 'RW')}") for db, s in expand(cfg, r.get("write", []))]
        out += [Grant(name, ("USAGE",), f"ROLE {ar_wh(wh)}") for wh in r.get("warehouses", [])]
    return out


def desired_grants(cfg):
    return access_grants(cfg) + composite_grants(cfg)


def managed_roles(cfg):
    return access_role_names(cfg) + list(cfg["functional_roles"]) + list(cfg["service_roles"])


def access_roles(cfg):
    """Create access roles and give them the only privileges in the system."""
    out = [(SECURITYADMIN, f"CREATE ROLE IF NOT EXISTS {r}") for r in access_role_names(cfg)]
    return out + [(SECURITYADMIN, g.sql()) for g in access_grants(cfg)]


def composite_roles(cfg):
    out = []
    for name, r in {**cfg["functional_roles"], **cfg["service_roles"]}.items():
        out.append((SECURITYADMIN, f"CREATE ROLE IF NOT EXISTS {name} COMMENT = '{_q(r['comment'])}'"))
    return out + [(SECURITYADMIN, g.sql()) for g in composite_grants(cfg)]


def platform_user(cfg):
    """One-time bootstrap: give the service user exactly SYSADMIN + SECURITYADMIN. Run by an
    ACCOUNTADMIN (see mdp.narrow); not part of render() because the day-to-day applier can't alter itself."""
    u = cfg["platform_user"]
    out = [(SECURITYADMIN, f"GRANT ROLE {r} TO USER {u['name']}") for r in u["roles"]]
    out += monitor_bootstrap(cfg)
    out.append((ACCOUNTADMIN,
        f"ALTER USER {u['name']} SET DEFAULT_ROLE = {u['default_role']}, "
        f"DEFAULT_WAREHOUSE = {u['default_warehouse']}, DEFAULT_SECONDARY_ROLES = ()"))
    return out


def render(cfg):
    return objects(cfg) + monitors(cfg) + access_roles(cfg) + composite_roles(cfg)
