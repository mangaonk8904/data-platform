import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
IDENT = re.compile(r"^[A-Z][A-Z0-9_]*$")
SENSITIVITIES = {"internal", "confidential", "restricted"}


class ConfigError(ValueError):
    pass


def load(path=None):
    path = Path(path) if path else ROOT / "config" / "access.yaml"
    cfg = yaml.safe_load(path.read_text())
    validate(cfg)
    return cfg


def all_schemas(cfg):
    return [(db, s) for db, d in cfg["databases"].items() for s in d["schemas"]]


def expand(cfg, refs):
    """Expand 'DB.SCHEMA' and 'DB.*' references to (db, schema) pairs, in declared order."""
    known = all_schemas(cfg)
    out = []
    for ref in refs:
        db, _, schema = ref.partition(".")
        matches = [p for p in known if p[0] == db and schema in ("*", p[1])]
        if not matches:
            raise ConfigError(f"unknown schema reference {ref!r}")
        out.extend(m for m in matches if m not in out)
    return out


def validate(cfg):
    names = []
    for section in ("warehouses", "databases", "functional_roles", "service_roles"):
        names += list(cfg.get(section, {}))
    for db, d in cfg["databases"].items():
        names += list(d["schemas"])
        for s, meta in d["schemas"].items():
            if meta.get("sensitivity") not in SENSITIVITIES:
                raise ConfigError(f"{db}.{s}: sensitivity must be one of {sorted(SENSITIVITIES)}")
            if not meta.get("owner_team"):
                raise ConfigError(f"{db}.{s}: owner_team is required")
    for n in names:
        if not IDENT.match(n):
            raise ConfigError(f"invalid identifier {n!r}: use UPPER_SNAKE_CASE")

    pu = cfg["platform_user"]
    if "ACCOUNTADMIN" in pu["roles"] or pu["default_role"] not in pu["roles"]:
        raise ConfigError("platform_user must not hold ACCOUNTADMIN and its default_role must be one of its roles")
    if pu["default_warehouse"] not in cfg["warehouses"]:
        raise ConfigError("platform_user.default_warehouse is not a declared warehouse")

    roles = {**cfg["functional_roles"], **cfg["service_roles"]}
    if set(cfg["functional_roles"]) & set(cfg["service_roles"]):
        raise ConfigError("role defined as both functional and service")
    for name, r in roles.items():
        for mode in ("read", "write"):
            expand(cfg, r.get(mode, []))
        for wh in r.get("warehouses", []):
            if wh not in cfg["warehouses"]:
                raise ConfigError(f"{name}: unknown warehouse {wh!r}")
        if not any(r.get(k) for k in ("read", "write", "warehouses")):
            raise ConfigError(f"{name}: grants nothing")
    for wh, w in cfg["warehouses"].items():
        if w["auto_suspend"] <= 0 or w["credit_quota"] <= 0:
            raise ConfigError(f"{wh}: auto_suspend and credit_quota must be positive")
    validate_governance(cfg)
    validate_hr_sync(cfg)
    validate_alerts(cfg)
    validate_ci_user(cfg)


def column_classes(cfg):
    """{'DB.SCHEMA.TABLE.COLUMN': CLASS} for every classified column."""
    g = cfg.get("governance", {})
    return {f"{t}.{c}": cls for t, cols in g.get("columns", {}).items() for c, cls in cols.items()}


def validate_governance(cfg):
    g = cfg.get("governance")
    if not g:
        return
    roles = {**cfg["functional_roles"], **cfg["service_roles"]}
    if len(g["tag"].split(".")) != 3 or not all(IDENT.match(p) for p in g["tag"].split(".")):
        raise ConfigError(f"governance.tag must be DB.SCHEMA.NAME, got {g['tag']!r}")
    if (g["tag"].split(".")[0], g["tag"].split(".")[1]) not in all_schemas(cfg):
        raise ConfigError(f"governance.tag {g['tag']!r} must live in a declared schema")
    for cls, c in g["classes"].items():
        if not IDENT.match(cls):
            raise ConfigError(f"invalid class name {cls!r}")
        for r in c.get("unmask", []):
            if r not in roles:
                raise ConfigError(f"class {cls}: unmask role {r!r} is not a declared role")
    known = set(all_schemas(cfg))
    for table in {**g.get("columns", {}), **g.get("row_access", {})}:
        parts = table.split(".")
        if len(parts) != 3 or (parts[0], parts[1]) not in known or not all(IDENT.match(p) for p in parts):
            raise ConfigError(f"unknown table reference {table!r}")
    for table, cols in g.get("columns", {}).items():
        for col, cls in cols.items():
            if not IDENT.match(col) or cls not in g["classes"]:
                raise ConfigError(f"{table}.{col}: bad column or unknown class {cls!r}")
    for table, ra in g.get("row_access", {}).items():
        if not IDENT.match(ra["column"]):
            raise ConfigError(f"{table}: bad row_access column")
        cls = g.get("columns", {}).get(table, {}).get(ra["column"])
        if cls is None or g["classes"][cls].get("mask", True):
            raise ConfigError(f"{table}.{ra['column']}: a row_access column must be classified with a "
                              f"mask: false class (Snowflake cannot mask a row-policy argument)")
        for r in list(ra.get("unrestricted", [])) + list(ra.get("regions", {})):
            if r not in roles:
                raise ConfigError(f"{table}: row_access role {r!r} is not a declared role")
        for r, regions in ra.get("regions", {}).items():
            if not regions or not all(re.fullmatch(r"[A-Za-z0-9_ -]+", x) for x in regions):
                raise ConfigError(f"{table}: bad regions for {r}")


def validate_hr_sync(cfg):
    h = cfg.get("hr_sync")
    if not h:
        return
    fr = set(cfg["functional_roles"])
    if not 0 < h["max_disable_fraction"] <= 1:
        raise ConfigError("hr_sync.max_disable_fraction must be in (0, 1]")
    for family, roles in h["job_family_roles"].items():
        for r in roles:
            if r not in fr:
                raise ConfigError(f"hr_sync.job_family_roles.{family}: {r!r} is not a functional role")
    for e in h.get("exceptions", []):
        if e["role"] not in fr:
            raise ConfigError(f"hr_sync exception for {e['employee']}: {e['role']!r} is not a functional role")
        if not e.get("reason") or not hasattr(e.get("expires"), "year"):
            raise ConfigError(f"hr_sync exception for {e['employee']}: needs a reason and a date `expires`")


def validate_alerts(cfg):
    a = cfg.get("alerts")
    if not a:
        return
    if not 0 < a["classifier_min_confidence"] <= 1:
        raise ConfigError("alerts.classifier_min_confidence must be in (0, 1]")
    if a["exception_warning_days"] < 0:
        raise ConfigError("alerts.exception_warning_days must be >= 0")
    for u in a.get("allowed_role_holders", []):
        if not IDENT.match(u):
            raise ConfigError(f"alerts.allowed_role_holders: invalid user {u!r}")


def validate_ci_user(cfg):
    u = cfg.get("ci_user")
    if not u:
        return
    if not IDENT.match(u["name"]) or u["name"] == cfg["platform_user"]["name"]:
        raise ConfigError("ci_user.name must be a valid identifier distinct from platform_user")
    if not set(u["roles"]) <= {"SYSADMIN", "SECURITYADMIN"} or u["default_role"] not in u["roles"]:
        raise ConfigError("ci_user may hold only SYSADMIN and SECURITYADMIN (never ACCOUNTADMIN)")
    if u["default_warehouse"] not in cfg["warehouses"]:
        raise ConfigError("ci_user.default_warehouse is not a declared warehouse")
