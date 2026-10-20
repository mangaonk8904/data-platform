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
