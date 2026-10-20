import pytest

from mdp.config import load
from mdp.reconcile import Atom, desired_atoms, diff, statement
from mdp.sqlgen import desired_grants, managed_roles, render


@pytest.fixture
def cfg():
    return load()


INV = {("TABLE", "CURATED.WORK"): ["CURATED.WORK.TASKS", "CURATED.WORK.PROJECTS"]}


def test_desired_expands_all_tables_against_inventory(cfg):
    d = desired_atoms(cfg, INV)
    ro = "AR_CURATED__WORK__RO"
    assert Atom(ro, "SELECT", "TABLE", "CURATED.WORK.TASKS") in d
    assert Atom(ro, "SELECT", "FUTURE_TABLE", "CURATED.WORK") in d
    # empty schemas contribute no per-table atoms, so they never show as perpetual drift
    assert not [a for a in d if a.kind == "TABLE" and a.target.startswith("CURATED.PAYMENTS")]


def test_identical_state_is_empty_plan(cfg):
    d = desired_atoms(cfg, INV)
    assert diff(d, set(d)) == ([], [])


def test_rogue_grant_is_revoked(cfg):
    d = desired_atoms(cfg, INV)
    rogue = Atom("AR_CURATED__WORK__RO", "DELETE", "TABLE", "CURATED.WORK.TASKS")
    to_add, to_revoke = diff(d, d | {rogue})
    assert to_add == [] and to_revoke == [rogue]
    assert statement("REVOKE", rogue) == "REVOKE DELETE ON TABLE CURATED.WORK.TASKS FROM ROLE AR_CURATED__WORK__RO"


def test_rogue_role_grant_is_revoked(cfg):
    d = desired_atoms(cfg, INV)
    rogue = Atom("FR_DATA_ANALYST", "USAGE", "ROLE", "AR_CURATED__EXPERTS_SENSITIVE__RO")
    _, to_revoke = diff(d, d | {rogue})
    assert to_revoke == [rogue]
    assert statement("REVOKE", rogue) == "REVOKE ROLE AR_CURATED__EXPERTS_SENSITIVE__RO FROM ROLE FR_DATA_ANALYST"


def test_missing_grant_is_added(cfg):
    d = desired_atoms(cfg, INV)
    gone = Atom("SVC_HEX", "USAGE", "ROLE", "AR_MARTS__EXEC__RO")
    assert gone in d
    to_add, to_revoke = diff(d, d - {gone})
    assert to_add == [gone] and to_revoke == []
    assert statement("GRANT", gone) == "GRANT ROLE AR_MARTS__EXEC__RO TO ROLE SVC_HEX"


def test_future_and_account_statements():
    f = Atom("R", "SELECT", "FUTURE_TABLE", "CURATED.WORK")
    assert statement("REVOKE", f) == "REVOKE SELECT ON FUTURE TABLES IN SCHEMA CURATED.WORK FROM ROLE R"
    db = Atom("R", "SELECT", "FUTURE_VIEW", "CURATED")
    assert statement("REVOKE", db) == "REVOKE SELECT ON FUTURE VIEWS IN DATABASE CURATED FROM ROLE R"
    assert statement("REVOKE", Atom("R", "CREATE DATABASE", "ACCOUNT", "X")) == "REVOKE CREATE DATABASE ON ACCOUNT FROM ROLE R"


def test_every_rendered_grant_is_declared(cfg):
    """sqlgen and the reconciler must share one source of truth."""
    declared = {g.grantee for g in desired_grants(cfg)}
    assert declared <= set(managed_roles(cfg))
    rendered = [s for r, s in render(cfg) if s.startswith("GRANT")]
    assert len(rendered) == len(desired_grants(cfg))
