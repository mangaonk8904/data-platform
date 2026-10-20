import copy

import pytest

from mdp.config import ConfigError, expand, load, validate
from mdp.sqlgen import SECURITYADMIN, ar_schema, render


@pytest.fixture
def cfg():
    return load()


def test_config_valid(cfg):
    assert cfg["databases"]["CURATED"]["schemas"]["EXPERTS_SENSITIVE"]["sensitivity"] == "restricted"


def test_wildcard_expansion(cfg):
    assert ("MARTS", "ML") in expand(cfg, ["MARTS.*"])
    assert len(expand(cfg, ["MARTS.*", "MARTS.ML"])) == 4  # no duplicates


def test_unknown_schema_rejected(cfg):
    bad = copy.deepcopy(cfg)
    bad["functional_roles"]["FR_FINANCE"]["read"].append("CURATED.NOPE")
    with pytest.raises(ConfigError):
        validate(bad)


def test_unknown_warehouse_rejected(cfg):
    bad = copy.deepcopy(cfg)
    bad["service_roles"]["SVC_HEX"]["warehouses"] = ["WH_MISSING"]
    with pytest.raises(ConfigError):
        validate(bad)


def test_lowercase_identifier_rejected(cfg):
    bad = copy.deepcopy(cfg)
    bad["warehouses"]["wh_bad"] = bad["warehouses"]["WH_ADMIN"]
    with pytest.raises(ConfigError):
        validate(bad)


def test_every_schema_is_managed_access(cfg):
    creates = [s for _, s in render(cfg) if s.startswith("CREATE SCHEMA")]
    assert creates and all("WITH MANAGED ACCESS" in s for s in creates)


def test_only_access_roles_get_object_privileges(cfg):
    for role, sql in render(cfg):
        if sql.startswith("GRANT") and " ON " in sql and "TO ROLE" in sql:
            target = sql.split("TO ROLE ")[1]
            assert target.startswith("AR_"), sql


def test_pii_schema_reachable_only_via_pii_reader_and_airflow(cfg):
    ro = ar_schema("CURATED", "EXPERTS_SENSITIVE", "RO")
    rw = ar_schema("CURATED", "EXPERTS_SENSITIVE", "RW")
    holders = {sql.split("TO ROLE ")[1] for _, sql in render(cfg)
               if sql.startswith("GRANT ROLE") and sql.split()[2] in (ro, rw)}
    assert holders == {rw, "FR_PII_READER", "SVC_AIRFLOW"}


def test_analyst_has_no_sensitive_or_raw_access(cfg):
    grants = [sql.split()[2] for _, sql in render(cfg)
              if sql.endswith("TO ROLE FR_DATA_ANALYST") and sql.startswith("GRANT ROLE")]
    assert not [g for g in grants if "SENSITIVE" in g or g.startswith("AR_RAW")]
    assert not [g for g in grants if g.endswith("__RW")]


def test_ordering_roles_after_objects(cfg):
    stmts = render(cfg)
    first_sec = next(i for i, (r, _) in enumerate(stmts) if r == SECURITYADMIN)
    assert all(not s.startswith("CREATE SCHEMA") for _, s in stmts[first_sec:])


def test_render_is_deterministic(cfg):
    assert render(cfg) == render(cfg)


def test_default_public_schema_dropped_everywhere(cfg):
    drops = {s for _, s in render(cfg) if s.startswith("DROP SCHEMA")}
    assert drops == {f"DROP SCHEMA IF EXISTS {db}.PUBLIC" for db in cfg["databases"]}


def test_day_to_day_render_needs_no_accountadmin(cfg):
    assert all(role != "ACCOUNTADMIN" for role, _ in render(cfg))


def test_platform_user_never_gets_accountadmin(cfg):
    from mdp.sqlgen import platform_user
    sql = [s for _, s in platform_user(cfg)]
    assert not any(s.startswith("GRANT ROLE ACCOUNTADMIN") for s in sql)
    assert "DEFAULT_SECONDARY_ROLES = ()" in sql[-1]


def test_platform_user_validation(cfg):
    bad = copy.deepcopy(cfg)
    bad["platform_user"]["roles"].append("ACCOUNTADMIN")
    with pytest.raises(ConfigError):
        validate(bad)
