import copy
from datetime import date

import pytest

from mdp.config import ROOT, ConfigError, load, validate
from mdp.hr_sync import SyncError, check_blast_radius, desired, plan, read_feed, statement, username

TODAY = date(2026, 10, 20)


@pytest.fixture
def cfg():
    return load()


@pytest.fixture
def day1():
    return read_feed(ROOT / "data" / "hr_feed_day1.csv")


@pytest.fixture
def day2():
    return read_feed(ROOT / "data" / "hr_feed_day2.csv")


def state_from(cfg, feed, today=TODAY):
    return {u: dict(employee_id=w["employee_id"], disabled=w["disabled"], roles=set(w["roles"]))
            for u, w in desired(cfg, feed, today).items()}


def by(changes, action=None, user=None):
    return [c for c in changes if (action is None or c.action == action) and (user is None or c.user == user)]


def test_username():
    assert username("Ava.Stone@example.com") == "AVA_STONE"
    assert username("o'brien+x@example.com") == "O_BRIEN_X"


def test_day1_from_empty_creates_everyone_with_job_roles(cfg, day1):
    ch = plan(cfg, day1, {}, TODAY)
    assert len(by(ch, "CREATE_USER")) == 10
    assert {c.role for c in by(ch, "GRANT", "AVA_STONE")} == {"FR_DATA_ANALYST"}
    assert by(ch, "GRANT", "KOFI_NOVAK") == []          # Engineering has no data roles
    assert all(c.reason == "joiner" for c in ch)


def test_exceptions_grant_and_expire(cfg, day1):
    ch = plan(cfg, day1, {}, TODAY)
    assert "FR_PII_READER" in {c.role for c in by(ch, "GRANT", "NOOR_HADDAD")}   # expires 2026-12-31
    assert "FR_PII_READER" not in {c.role for c in by(ch, "GRANT", "MEI_CHEN")}  # expired 2026-09-30


def test_expired_exception_is_revoked_from_existing_holder(cfg, day1):
    cur = state_from(cfg, day1, date(2026, 9, 1))  # exception still valid then
    assert "FR_PII_READER" in cur["MEI_CHEN"]["roles"]
    ch = plan(cfg, day1, cur, TODAY)
    assert [(c.action, c.role) for c in ch] == [("REVOKE", "FR_PII_READER")]


def test_steady_state_is_empty(cfg, day1):
    assert plan(cfg, day1, state_from(cfg, day1), TODAY) == []


def test_day2_joiner_mover_leaver_onleave(cfg, day1, day2):
    ch = plan(cfg, day2, state_from(cfg, day1), TODAY)
    assert [c.action for c in by(ch, user="INES_CHEN")] == ["CREATE_USER", "GRANT"]
    assert [(c.action, c.role) for c in by(ch, user="ARJUN_OKAFOR")] == [
        ("REVOKE", "FR_DATA_ANALYST"), ("GRANT", "FR_DATA_SCIENTIST")]
    assert [(c.action, c.role, c.reason) for c in by(ch, user="OMAR_ROSSI")] == [
        ("REVOKE", "FR_SUPPORT", "leaver"), ("DISABLE", "", "leaver")]
    assert [(c.action, c.reason) for c in by(ch, user="MATEO_SILVA")] == [("DISABLE", "on leave")]  # roles kept


def test_removals_come_before_additions(cfg, day1, day2):
    ch = plan(cfg, day2, state_from(cfg, day1), TODAY)
    first_add = next(i for i, c in enumerate(ch) if c.action in ("GRANT", "CREATE_USER", "ENABLE"))
    assert all(c.action in ("GRANT", "CREATE_USER", "ENABLE") for c in ch[first_add:])


def test_return_from_leave_enables_user(cfg, day1, day2):
    on_leave = state_from(cfg, day2)
    ch = plan(cfg, day1, on_leave, TODAY)  # day1 feed has Mateo active again
    assert ("ENABLE", "MATEO_SILVA") in {(c.action, c.user) for c in ch}


def test_absent_from_feed_is_a_leaver(cfg, day1):
    feed = [r for r in day1 if r["employee_id"] != "E010"]
    cur = state_from(cfg, day1)
    cur["KOFI_NOVAK"]["roles"] = {"FR_SUPPORT"}
    ch = plan(cfg, feed, cur, TODAY)
    assert [(c.action, c.reason) for c in by(ch, user="KOFI_NOVAK")] == [
        ("REVOKE", "absent from feed"), ("DISABLE", "absent from feed")]


def test_manual_grant_outside_feed_is_revoked(cfg, day1):
    cur = state_from(cfg, day1)
    cur["AVA_STONE"]["roles"].add("FR_FINANCE")
    ch = plan(cfg, day1, cur, TODAY)
    assert [(c.action, c.role) for c in ch] == [("REVOKE", "FR_FINANCE")]


def test_future_start_is_ignored_and_terminated_never_provisioned(cfg, day1):
    feed = [dict(r) for r in day1]
    feed[0]["start_date"] = "2027-01-04"
    feed[1]["status"] = "terminated"
    ch = plan(cfg, feed, {}, TODAY)
    assert by(ch, user="AVA_STONE") == [] and by(ch, user="LIAM_PATEL") == []


def test_past_end_date_counts_as_leaver_even_if_status_active(cfg, day1):
    feed = [dict(r) for r in day1]
    feed[0]["end_date"] = "2026-10-19"
    cur = state_from(cfg, day1)
    ch = plan(cfg, feed, cur, TODAY)
    assert [c.action for c in by(ch, user="AVA_STONE")] == ["REVOKE", "DISABLE"]


def test_truncated_feed_trips_blast_radius_check(cfg, day1):
    cur = state_from(cfg, day1)
    ch = plan(cfg, day1[:3], cur, TODAY)   # 7 of 10 vanish
    with pytest.raises(SyncError):
        check_blast_radius(cfg, ch, cur)


def test_normal_day2_is_within_blast_radius(cfg, day1, day2):
    cur = state_from(cfg, day1)
    check_blast_radius(cfg, plan(cfg, day2, cur, TODAY), cur)


def test_empty_feed_rejected(tmp_path):
    f = tmp_path / "f.csv"
    f.write_text("employee_id,email,full_name,job_family,status,start_date,end_date\n")
    with pytest.raises(SyncError):
        read_feed(f)


def test_unknown_job_family_and_collision_rejected(cfg, day1):
    feed = [dict(r) for r in day1]
    feed[0]["job_family"] = "Wizardry"
    with pytest.raises(SyncError):
        plan(cfg, feed, {}, TODAY)
    feed = [dict(r) for r in day1]
    feed[1]["email"] = "ava.stone@other.org"
    with pytest.raises(SyncError):
        plan(cfg, feed, {}, TODAY)


def test_statements_are_scoped_and_quoted(cfg, day1):
    ch = plan(cfg, day1, {}, TODAY)
    create = statement(by(ch, "CREATE_USER", "AVA_STONE")[0], "ava.stone@example.com", "Ava O'Stone")
    assert "DEFAULT_SECONDARY_ROLES = ()" in create and "managed-by=hr-sync" in create and "O''Stone" in create
    assert statement(by(ch, "GRANT", "AVA_STONE")[0]) == "GRANT ROLE FR_DATA_ANALYST TO USER AVA_STONE"


def test_hr_sync_config_validation(cfg):
    bad = copy.deepcopy(cfg)
    bad["hr_sync"]["job_family_roles"]["Analytics"] = ["AR_RAW__X__RO"]
    with pytest.raises(ConfigError):
        validate(bad)
    bad = copy.deepcopy(cfg)
    del bad["hr_sync"]["exceptions"][0]["reason"]
    with pytest.raises(ConfigError):
        validate(bad)
