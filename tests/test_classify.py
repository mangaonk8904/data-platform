import copy

import pytest

from mdp.classify import by_name, by_values, detect, evaluate, judge, luhn
from mdp.config import load


@pytest.fixture
def cfg():
    return load()


EMAILS = [f"user{i}@example.com" for i in range(10)]


@pytest.mark.parametrize("name,cls", [
    ("email", "PII_DIRECT"), ("contact_email", "PII_DIRECT"), ("FULL_NAME", "PII_DIRECT"), ("ip_address", "PII_DIRECT"), ("client_ip", "PII_DIRECT"), ("ip", "PII_DIRECT"),
    ("tax_id", "PII_SENSITIVE"), ("SSN", "PII_SENSITIVE"), ("date_of_birth", "PII_SENSITIVE"), ("phone_number", "PII_SENSITIVE"),
    ("street_address", "PII_SENSITIVE"), ("zip_code", "PII_SENSITIVE"), ("iban", "PII_SENSITIVE"),
    ("hourly_rate_usd", "FINANCIAL"), ("amount_usd", "FINANCIAL"), ("salary", "FINANCIAL"),
])
def test_name_rules(name, cls):
    assert by_name(name).cls == cls


@pytest.mark.parametrize("name", ["expert_id", "task_id", "hours", "quality_score", "status", "region", "tier",
                                  "method", "name", "domain", "started_at", "country", "ip_ranking", "ipo_date", "recipe"])
def test_name_rules_have_no_false_positives(name):
    assert by_name(name) is None


def test_name_boundaries():
    assert by_name("company_name") is None and by_name("pan") is not None and by_name("expand") is None
    assert by_name("email_address").cls == "PII_DIRECT"   # not mistaken for a postal address


def test_value_rules():
    assert by_values(EMAILS).cls == "PII_DIRECT"
    assert by_values([f"{100+i}-45-{6000+i}" for i in range(8)]).cls == "PII_SENSITIVE"
    assert by_values([f"+1-555-{1000+i}" for i in range(8)]).cls == "PII_SENSITIVE"
    assert by_values([f"10.0.{i}.7" for i in range(8)]).cls == "PII_DIRECT"
    assert by_values(["4111111111111111"] * 6).cls == "PII_SENSITIVE"
    assert by_values(["DE89370400440532013000"] * 6).cls == "PII_SENSITIVE"


def test_value_rules_need_enough_clean_samples():
    assert by_values(EMAILS[:3]) is None                       # too few samples
    assert by_values(EMAILS[:2] + ["n/a"] * 8) is None         # below match ratio
    assert by_values([None, "", " "] + EMAILS[:2]) is None     # blanks ignored, still too few
    assert by_values([str(i) for i in range(1000, 1010)]) is None  # plain numbers are not cards or phones


def test_luhn():
    assert luhn("4111111111111111") and not luhn("4111111111111112")


def test_signals_combine():
    both = detect("contact_email", EMAILS)
    assert both.confidence > detect("contact_email").confidence and both.confidence > detect("x", EMAILS).confidence - 1e-9
    assert detect("notes", EMAILS).cls == "PII_DIRECT"                      # value alone is enough
    conflict = detect("tax_id", EMAILS)                                      # values win over a misleading name
    assert conflict.cls == "PII_DIRECT" and "name suggested" in conflict.evidence


def test_configured_columns_are_clean(cfg):
    cols = {"CURATED.EXPERTS_SENSITIVE.EXPERT_PII": {"TAX_ID": [], "PHONE": [], "DATE_OF_BIRTH": []},
            "CURATED.EXPERTS.EXPERTS": {"EMAIL": [], "FULL_NAME": [], "HOURLY_RATE_USD": [], "EXPERT_ID": []}}
    assert evaluate(cfg, cols) == []


def test_unclassified_value_match_is_high(cfg):
    f = judge(cfg, "CURATED.WORK.NOTES.CONTACT", detect("contact", EMAILS))
    assert (f.severity, f.kind, f.suggested, f.current) == ("HIGH", "UNCLASSIFIED", "PII_DIRECT", "-")


def test_unclassified_name_only_is_medium(cfg):
    f = judge(cfg, "CURATED.WORK.NOTES.EMAIL", detect("email"))
    assert (f.severity, f.kind) == ("MEDIUM", "UNCLASSIFIED")


def test_explicit_general_but_looks_sensitive_is_high(cfg):
    bad = copy.deepcopy(cfg)
    bad["governance"]["columns"]["CURATED.CUSTOMERS.CUSTOMERS"]["NAME"] = "GENERAL"
    f = judge(bad, "CURATED.CUSTOMERS.CUSTOMERS.REGION", None)
    assert f is None
    bad["governance"]["columns"]["CURATED.EXPERTS.EXPERTS"]["EMAIL"] = "GENERAL"
    f = judge(bad, "CURATED.EXPERTS.EXPERTS.EMAIL", detect("email", EMAILS))
    assert (f.severity, f.kind) == ("HIGH", "UNDER_CLASSIFIED")


def test_different_class_is_low(cfg):
    f = judge(cfg, "CURATED.EXPERTS.EXPERTS.EMAIL", detect("x", [f"{i}{i}{i}-45-{6000+i}" for i in range(8)]))
    assert (f.severity, f.kind, f.suggested) == ("LOW", "DIFFERENT_CLASS", "PII_SENSITIVE")


def test_min_confidence_filters_name_only(cfg):
    assert judge(cfg, "A.B.C.EMAIL", detect("email"), min_conf=0.8) is None


def test_findings_sorted_most_severe_first(cfg):
    tables = {"CURATED.WORK.N": {"EMAIL": [], "CONTACT": EMAILS}}
    assert [f.severity for f in evaluate(cfg, tables)] == ["HIGH", "MEDIUM"]
