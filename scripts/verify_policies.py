"""Live check of masking and row access: run as each role and assert what it actually sees.
Temporarily grants roles to PLATFORM_ADMIN; always revokes them again."""
import sys

from mdp.conn import connect, current_user

USER = current_user()  # whoever is running this
E, C, P, PAY = ("CURATED.EXPERTS.EXPERTS", "CURATED.CUSTOMERS.CUSTOMERS",
                "CURATED.EXPERTS_SENSITIVE.EXPERT_PII", "CURATED.PAYMENTS.PAYMENTS")
MASK = "***MASKED***"

# role -> list of (description, sql returning one value, expected: 'masked' | 'visible' | int | 'denied')
CHECKS = {
    "FR_DATA_ANALYST": [
        ("email masked", f"SELECT MAX(email) FROM {E}", "masked"),
        ("full_name masked", f"SELECT MAX(full_name) FROM {E}", "masked"),
        ("hourly_rate masked", f"SELECT MAX(hourly_rate_usd) FROM {E}", "masked"),
        ("country visible", f"SELECT MAX(country) FROM {E}", "visible"),
        ("customers: NA+EMEA rows only", f"SELECT COUNT(*) FROM {C}", "NA_EMEA"),
        ("customers: no APAC", f"SELECT COUNT(*) FROM {C} WHERE region = 'APAC'", 0),
        ("contract_value masked", f"SELECT MAX(contract_value_usd) FROM {C}", "masked"),
    ],
    "FR_DATA_SCIENTIST": [
        ("email masked", f"SELECT MAX(email) FROM {E}", "masked"),
        ("hourly_rate masked", f"SELECT MAX(hourly_rate_usd) FROM {E}", "masked"),
        ("customers denied", f"SELECT COUNT(*) FROM {C}", "denied"),
    ],
    "FR_SUPPORT": [
        ("email visible", f"SELECT MAX(email) FROM {E}", "visible"),
        ("full_name visible", f"SELECT MAX(full_name) FROM {E}", "visible"),
        ("hourly_rate masked", f"SELECT MAX(hourly_rate_usd) FROM {E}", "masked"),
    ],
    "FR_PII_READER": [
        ("tax_id visible", f"SELECT MAX(tax_id) FROM {P}", "visible"),
        ("date_of_birth visible", f"SELECT MAX(date_of_birth) FROM {P}", "visible"),
        ("payments denied", f"SELECT COUNT(*) FROM {PAY}", "denied"),
    ],
    "FR_FINANCE": [
        ("amount visible", f"SELECT MAX(amount_usd) FROM {PAY}", "visible"),
        ("customers: all rows", f"SELECT COUNT(*) FROM {C}", "ALL"),
        ("contract_value visible", f"SELECT MAX(contract_value_usd) FROM {C}", "visible"),
        ("experts denied", f"SELECT COUNT(*) FROM {E}", "denied"),
    ],
    "FR_DATA_PLATFORM": [
        ("customers denied", f"SELECT COUNT(*) FROM {C}", "denied"),
    ],
    "SVC_AIRFLOW": [
        ("email visible", f"SELECT MAX(email) FROM {E}", "visible"),
        ("hourly_rate visible", f"SELECT MAX(hourly_rate_usd) FROM {E}", "visible"),
        ("tax_id visible", f"SELECT MAX(tax_id) FROM {P}", "visible"),
        ("customers: all rows", f"SELECT COUNT(*) FROM {C}", "ALL"),
    ],
    "SVC_HEX": [
        ("customers denied", f"SELECT COUNT(*) FROM {C}", "denied"),
    ],
}
WAREHOUSE = {"FR_DATA_PLATFORM": "WH_ADMIN", "SVC_AIRFLOW": "WH_TRANSFORM"}  # default WH_ANALYTICS


def observe(cur, sql):
    try:
        cur.execute(sql)
    except Exception:
        return "denied"
    v = cur.fetchone()[0]
    if isinstance(v, str):
        return "masked" if v == MASK else "visible"
    return v


def classify(v, expected, totals):
    if isinstance(v, int) and expected in ("NA_EMEA", "ALL") or expected == 0:
        return v == (totals[expected] if isinstance(expected, str) else expected)
    if expected == "masked":
        return v == "masked" or v is None
    if expected == "visible":
        return v not in ("masked", "denied", None)
    return v == expected


failures = 0
with connect(role="SECURITYADMIN") as conn:
    cur = conn.cursor()
    try:
        cur.execute("GRANT ROLE SVC_AIRFLOW TO USER " + USER)
        cur.execute("USE ROLE SVC_AIRFLOW")
        cur.execute("USE SECONDARY ROLES NONE")
        cur.execute("USE WAREHOUSE WH_TRANSFORM")
        cur.execute(f"SELECT COUNT(*), COUNT_IF(region IN ('NA','EMEA')) FROM {C}")
        total, na_emea = cur.fetchone()
        totals = {"ALL": total, "NA_EMEA": na_emea}
        print(f"ground truth (SVC_AIRFLOW): {total} customers, {na_emea} in NA+EMEA")
        assert 0 < na_emea < total, "seed data must contain APAC customers for the row check to mean anything"
        cur.execute("USE ROLE SECURITYADMIN")
        for role, checks in CHECKS.items():
            if role != "SVC_AIRFLOW":
                cur.execute(f"GRANT ROLE {role} TO USER {USER}")
            cur.execute(f"USE ROLE {role}")
            cur.execute("USE SECONDARY ROLES NONE")  # else ACCOUNTADMIN leaks through
            cur.execute(f"USE WAREHOUSE {WAREHOUSE.get(role, 'WH_ANALYTICS')}")
            for desc, sql, expected in checks:
                got = observe(cur, sql)
                ok = classify(got, expected, totals)
                failures += not ok
                print(f"{'PASS' if ok else 'FAIL'}  {role:18} {desc:32} got={got!s:10} expected={expected}")
            cur.execute("USE ROLE SECURITYADMIN")
    finally:
        cur.execute("USE ROLE SECURITYADMIN")
        for role in CHECKS:
            cur.execute(f"REVOKE ROLE {role} FROM USER {USER}")
sys.exit(1 if failures else 0)
