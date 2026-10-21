"""Live check: run the same probes as each role and assert allowed/denied.
Temporarily grants roles to PLATFORM_ADMIN; always revokes them again."""
import sys

from mdp.conn import connect, current_user

USER = current_user()  # whoever is running this
PROBES = {  # role -> {table: should_be_readable}
    "FR_DATA_ANALYST": {"CURATED.WORK.TASKS": True, "CURATED.EXPERTS.EXPERTS": True, "CURATED.CUSTOMERS.CUSTOMERS": True,
                        "CURATED.EXPERTS_SENSITIVE.EXPERT_PII": False, "CURATED.PAYMENTS.PAYMENTS": False},
    "FR_FINANCE": {"CURATED.PAYMENTS.PAYMENTS": True, "CURATED.CUSTOMERS.CUSTOMERS": True,
                   "CURATED.EXPERTS.EXPERTS": False, "CURATED.EXPERTS_SENSITIVE.EXPERT_PII": False},
    "FR_PII_READER": {"CURATED.EXPERTS_SENSITIVE.EXPERT_PII": True, "CURATED.PAYMENTS.PAYMENTS": False},
    "FR_DATA_PLATFORM": {"CURATED.EXPERTS.EXPERTS": False, "CURATED.EXPERTS_SENSITIVE.EXPERT_PII": False},
    "SVC_HEX": {"CURATED.WORK.TASKS": False, "CURATED.EXPERTS.EXPERTS": False},
    "SVC_AIRFLOW": {"CURATED.EXPERTS_SENSITIVE.EXPERT_PII": True, "CURATED.WORK.TASKS": True},
}

WAREHOUSE = {"FR_DATA_PLATFORM": "WH_ADMIN", "SVC_AIRFLOW": "WH_TRANSFORM"}  # default WH_ANALYTICS
failures = 0
with connect(role="SECURITYADMIN") as conn:
    cur = conn.cursor()
    cur.execute("SHOW SCHEMAS IN DATABASE CURATED")
    cols = [d[0] for d in cur.description]
    schemas = [dict(zip(cols, r, strict=True)) for r in cur.fetchall() if r[1] != "INFORMATION_SCHEMA"]
    unmanaged = [r["name"] for r in schemas if "MANAGED ACCESS" not in (r["options"] or "")]
    print("managed-access schemas:", "ok" if not unmanaged else f"MISSING {unmanaged}")
    failures += bool(unmanaged)
    try:
        for role, probes in PROBES.items():
            cur.execute(f"GRANT ROLE {role} TO USER {USER}")
            cur.execute(f"USE ROLE {role}")
            cur.execute("USE SECONDARY ROLES NONE")  # else ACCOUNTADMIN leaks through
            cur.execute(f"USE WAREHOUSE {WAREHOUSE.get(role, 'WH_ANALYTICS')}")
            for table, expect in probes.items():
                try:
                    cur.execute(f"SELECT COUNT(*) FROM {table}")
                    got = True
                except Exception:
                    got = False
                ok = got == expect
                failures += not ok
                print(f"{'PASS' if ok else 'FAIL'}  {role:18} {table:42} readable={got} expected={expect}")
            cur.execute("USE ROLE SECURITYADMIN")
    finally:
        cur.execute("USE ROLE SECURITYADMIN")
        for role in PROBES:
            cur.execute(f"REVOKE ROLE {role} FROM USER {USER}")
sys.exit(1 if failures else 0)
