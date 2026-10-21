from datetime import date

import pytest

from mdp.classify import Finding
from mdp.config import load
from mdp.drift import (
    Event,
    classifier_events,
    diff_events,
    exception_events,
    grant_events,
    hr_events,
    slack_payload,
    worst,
)
from mdp.hr_sync import Change
from mdp.reconcile import Atom

TODAY = date(2026, 10, 20)


@pytest.fixture
def cfg():
    return load()


def test_grant_events_severity():
    ev = grant_events([Atom("R", "SELECT", "TABLE", "A.B.C")], [Atom("R", "DELETE", "TABLE", "A.B.C")], ["AR_X"], ["FR_Y"])
    assert sorted((e.severity, e.detail.split(":")[0]) for e in ev) == [
        ("HIGH", "declared role does not exist"), ("HIGH", "undeclared privilege held"),
        ("MEDIUM", "declared privilege missing"), ("MEDIUM", "role looks managed but is not in access.yaml")]


def test_fingerprints_are_stable_and_unique():
    a = grant_events([], [Atom("R", "DELETE", "TABLE", "A.B.C")], [])
    b = grant_events([], [Atom("R", "DELETE", "TABLE", "A.B.C")], [])
    assert a[0].fingerprint == b[0].fingerprint
    assert a[0].fingerprint != grant_events([], [Atom("R", "INSERT", "TABLE", "A.B.C")], [])[0].fingerprint


def test_expired_exception_still_held_is_high(cfg):
    ev = exception_events(cfg, {"MEI_CHEN": {"FR_FINANCE", "FR_PII_READER"}}, {"MEI_CHEN"}, TODAY)
    assert [(e.severity, e.fingerprint) for e in ev] == [("HIGH", "exceptions:expired:MEI_CHEN:FR_PII_READER")]


def test_expired_and_revoked_is_quiet(cfg):
    assert exception_events(cfg, {"MEI_CHEN": {"FR_FINANCE"}}, {"MEI_CHEN"}, TODAY) == []


def test_active_exception_is_quiet_and_warns_near_expiry(cfg):
    holders = {"NOOR_HADDAD": {"FR_FINANCE", "FR_PII_READER"}}
    assert exception_events(cfg, holders, {"NOOR_HADDAD"}, TODAY) == []          # 72 days left
    soon = exception_events(cfg, holders, {"NOOR_HADDAD"}, date(2026, 12, 20))   # 11 days left
    assert [(e.severity, e.check) for e in soon] == [("LOW", "exceptions")] and "11 days" in soon[0].detail


def test_additive_role_without_any_exception_is_high(cfg):
    ev = exception_events(cfg, {"ZOE_KIM": {"FR_DATA_PLATFORM", "FR_PII_READER"}}, {"ZOE_KIM"}, TODAY)
    assert [e.fingerprint for e in ev] == ["exceptions:noexception:ZOE_KIM:FR_PII_READER"]


def test_unmanaged_holder_flagged_unless_allowed(cfg):
    holders = {"ROGUE": {"FR_FINANCE"}, "PLATFORM_ADMIN": {"FR_FINANCE", "FR_PII_READER"}}
    ev = exception_events(cfg, holders, set(), TODAY)
    assert [e.fingerprint for e in ev] == ["exceptions:unmanaged:ROGUE"]


def test_classifier_events():
    f = Finding("HIGH", "UNCLASSIFIED", "CURATED.WORK.N.C", "PII_DIRECT", "-", 0.97, "5/5 sampled values are email addresses")
    ev = classifier_events([f], ["RAW.X.Y"])
    assert ev[0].severity == "HIGH" and "email addresses" in ev[0].detail and ev[1].severity == "LOW"


def test_hr_events():
    ev = hr_events([Change("REVOKE", "OMAR_ROSSI", "FR_SUPPORT", "leaver", "E008")])
    assert ev[0].severity == "MEDIUM" and "leaver" in ev[0].detail


def test_diff_dedupes_standing_problems():
    e1, e2 = Event("c", "HIGH", "c:1", "s", "d"), Event("c", "LOW", "c:2", "s", "d")
    new, resolved = diff_events([e1, e2], {"c:1", "c:3"})
    assert [e.fingerprint for e in new] == ["c:2"] and resolved == ["c:3"]
    assert diff_events([e1], {"c:1"}) == ([], [])          # unchanged: no alert
    assert diff_events([e1], set())[0] == [e1]             # reappearing after resolve alerts again


def test_new_events_sorted_by_severity():
    lo, hi = Event("c", "LOW", "c:a", "s", "d"), Event("c", "HIGH", "c:z", "s", "d")
    assert [e.severity for e in diff_events([lo, hi], set())[0]] == ["HIGH", "LOW"]


def test_worst():
    assert worst([]) is None
    assert worst([Event("c", "LOW", "x", "s", "d"), Event("c", "MEDIUM", "y", "s", "d")]) == 1


def test_slack_payload_truncates():
    evs = [Event("c", "HIGH", f"c:{i}", "s", "d") for i in range(25)]
    text = slack_payload(evs, ["old:1"])["text"]
    assert "25 new, 1 resolved" in text and "…and 5 more" in text and "resolved old:1" in text
