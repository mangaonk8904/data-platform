import copy

import pytest

from mdp.config import ConfigError, load, validate
from mdp.governance import (Atom, check_columns, definitions, desired_atoms, diff, family_of, mask_body,
                            rap_body, statement)


@pytest.fixture
def cfg():
    return load()


def test_family_of():
    assert family_of("VARCHAR(16777216)") == "STRING"
    assert family_of("NUMBER(8,2)") == "NUMBER"
    assert family_of("DATE") == "DATE"
    assert family_of("TIMESTAMP_NTZ(9)") is None


def test_unknown_unmask_role_rejected(cfg):
    bad = copy.deepcopy(cfg)
    bad["governance"]["classes"]["PII_DIRECT"]["unmask"].append("FR_NOPE")
    with pytest.raises(ConfigError):
        validate(bad)


def test_unknown_class_on_column_rejected(cfg):
    bad = copy.deepcopy(cfg)
    bad["governance"]["columns"]["CURATED.EXPERTS.EXPERTS"]["EMAIL"] = "SECRET"
    with pytest.raises(ConfigError):
        validate(bad)


def test_unknown_table_schema_rejected(cfg):
    bad = copy.deepcopy(cfg)
    bad["governance"]["columns"]["CURATED.NOPE.T"] = {"A": "GENERAL"}
    with pytest.raises(ConfigError):
        validate(bad)


def test_definitions_need_only_sysadmin(cfg):
    assert {role for role, _ in definitions(cfg)} == {"SYSADMIN"}


def test_account_level_grants_are_isolated_in_bootstrap(cfg):
    from mdp.governance import bootstrap
    assert {role for role, _ in bootstrap(cfg)} == {"ACCOUNTADMIN"}
    assert len(bootstrap(cfg)) == 3
    assert not any(s.startswith("GRANT") for _, s in definitions(cfg))


def test_policies_are_never_replaced(cfg):
    assert not any("CREATE OR REPLACE" in s for _, s in definitions(cfg))


def test_definitions_deterministic(cfg):
    assert definitions(cfg) == definitions(cfg)


def test_mask_body_only_unmasks_declared_roles(cfg):
    body = mask_body(cfg, "STRING")
    assert "IS_ROLE_IN_SESSION('FR_PII_READER')" in body
    assert "FR_DATA_ANALYST" not in body
    assert body.endswith("ELSE '***MASKED***' END") and "'GENERAL'" not in body
    assert mask_body(cfg, "NUMBER").endswith("ELSE NULL END")


def test_unmasked_classes_are_not_tagged(cfg):
    assert not any(a.kind == "COLUMN_TAG" and a.value == "GENERAL" for a in desired_atoms(cfg))


def test_row_policy_column_must_not_be_masked(cfg):
    bad = copy.deepcopy(cfg)
    bad["governance"]["columns"]["CURATED.CUSTOMERS.CUSTOMERS"]["REGION"] = "PII_DIRECT"
    with pytest.raises(ConfigError):
        validate(bad)


def test_pii_sensitive_not_unmasked_for_support(cfg):
    arm = [a for a in mask_body(cfg, "STRING").split("WHEN ") if "'PII_SENSITIVE'" in a][0]
    assert "FR_SUPPORT" not in arm


def test_rap_body_default_deny_for_unlisted_roles(cfg):
    ra = cfg["governance"]["row_access"]["CURATED.CUSTOMERS.CUSTOMERS"]
    body = rap_body("CURATED.CUSTOMERS.CUSTOMERS", ra)
    assert "FR_FINANCE" in body and "FR_DATA_ANALYST" not in body  # analyst only via entitlements
    assert "REGION_ACCESS" in body


def test_entitlements_rows_match_config(cfg):
    ins = [s for _, s in definitions(cfg) if s.startswith("INSERT")]
    assert len(ins) == 1 and "'FR_DATA_ANALYST', 'NA'" in ins[0] and "'EMEA'" in ins[0]
    assert "APAC" not in ins[0]


def test_desired_atoms_cover_every_classified_column(cfg):
    atoms = desired_atoms(cfg)
    assert Atom("COLUMN_TAG", "CURATED.EXPERTS_SENSITIVE.EXPERT_PII.TAX_ID", "PII_SENSITIVE") in atoms
    assert sum(a.kind == "TAG_MASK" for a in atoms) == 3
    assert sum(a.kind == "TABLE_RAP" for a in atoms) == 1


def test_statements(cfg):
    a = Atom("COLUMN_TAG", "CURATED.EXPERTS.EXPERTS.EMAIL", "PII_DIRECT")
    assert statement("ADD", a, cfg) == (
        "ALTER TABLE CURATED.EXPERTS.EXPERTS MODIFY COLUMN EMAIL SET TAG GOVERNANCE.TAGS.DATA_CLASS = 'PII_DIRECT'")
    assert statement("REMOVE", a, cfg).endswith("UNSET TAG GOVERNANCE.TAGS.DATA_CLASS")
    r = Atom("TABLE_RAP", "CURATED.CUSTOMERS.CUSTOMERS", "GOVERNANCE.POLICIES.RAP_X(REGION)")
    assert statement("ADD", r, cfg).endswith("ADD ROW ACCESS POLICY GOVERNANCE.POLICIES.RAP_X ON (REGION)")
    assert statement("REMOVE", r, cfg).endswith("DROP ROW ACCESS POLICY GOVERNANCE.POLICIES.RAP_X")


def test_diff_detects_wrong_and_missing_tags(cfg):
    desired = desired_atoms(cfg)
    actual = set(desired)
    actual.discard(Atom("COLUMN_TAG", "CURATED.EXPERTS.EXPERTS.EMAIL", "PII_DIRECT"))
    actual.add(Atom("COLUMN_TAG", "CURATED.EXPERTS.EXPERTS.EMAIL", "GENERAL"))  # downgraded by hand
    add, remove = diff(desired, actual)
    assert add == [Atom("COLUMN_TAG", "CURATED.EXPERTS.EXPERTS.EMAIL", "PII_DIRECT")]
    assert remove == [Atom("COLUMN_TAG", "CURATED.EXPERTS.EXPERTS.EMAIL", "GENERAL")]


def _live(cfg):
    return {t: {c: "VARCHAR(10)" for c in cols} for t, cols in cfg["governance"]["columns"].items()}


def test_check_clean(cfg):
    live = _live(cfg)
    live["CURATED.EXPERTS.EXPERTS"]["HOURLY_RATE_USD"] = "NUMBER(8,2)"
    live["CURATED.CUSTOMERS.CUSTOMERS"]["CONTRACT_VALUE_USD"] = "NUMBER(12,2)"
    live["CURATED.PAYMENTS.PAYMENTS"]["AMOUNT_USD"] = "NUMBER(10,2)"
    live["CURATED.EXPERTS_SENSITIVE.EXPERT_PII"]["DATE_OF_BIRTH"] = "DATE"
    assert check_columns(cfg, live) == []


def test_check_flags_new_unclassified_column(cfg):
    live = _live(cfg)
    live["CURATED.EXPERTS_SENSITIVE.EXPERT_PII"]["PASSPORT_NO"] = "VARCHAR(10)"
    assert any("PASSPORT_NO: unclassified" in f for f in check_columns(cfg, live))


def test_check_flags_unclassified_table(cfg):
    live = _live(cfg)
    live["CURATED.PAYMENTS.REFUNDS"] = {"AMOUNT": "NUMBER(10,2)"}
    assert any("REFUNDS" in f and "no classification" in f for f in check_columns(cfg, live))


def test_check_flags_sensitive_column_of_unmaskable_type(cfg):
    live = _live(cfg)
    live["CURATED.EXPERTS_SENSITIVE.EXPERT_PII"]["TAX_ID"] = "VARIANT"
    assert any("TAX_ID" in f and "would be readable" in f for f in check_columns(cfg, live))


def test_check_flags_missing_table_and_column(cfg):
    live = _live(cfg)
    del live["CURATED.PAYMENTS.PAYMENTS"]
    del live["CURATED.EXPERTS.EXPERTS"]["EMAIL"]
    out = check_columns(cfg, live)
    assert any("PAYMENTS" in f and "does not exist" in f for f in out)
    assert any("EMAIL" in f and "missing from the table" in f for f in out)
