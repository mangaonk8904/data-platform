"""Live demo: inject three real problems, watch the drift monitor alert once, fix them, watch it resolve.

  1. an unclassified table full of emails and phone numbers in a schema Phase 3 doesn't police
  2. an expired PII exception whose role was never revoked (MEI_CHEN)
  3. a stray DELETE grant on an analyst-facing table
"""
import subprocess
import sys

from mdp.conn import connect

TABLE = "CURATED.WORK.TASK_NOTES"


def run(*args):
    out = subprocess.run([sys.executable, "-m", *args], capture_output=True, text=True)
    lines = [line for line in out.stdout.splitlines() if line.strip()]
    print("\n".join("   " + line for line in lines))
    return out.returncode


def sql(role, *stmts, warehouse="WH_ADMIN"):
    with connect(role=role, warehouse=warehouse) as conn:
        cur = conn.cursor()
        for s in stmts:
            cur.execute(s)


def cleanup():
    sql("SYSADMIN", f"DROP TABLE IF EXISTS {TABLE}")
    sql("SECURITYADMIN", "REVOKE ROLE FR_PII_READER FROM USER MEI_CHEN",
        "REVOKE DELETE ON TABLE CURATED.WORK.PROJECTS FROM ROLE FR_DATA_ANALYST")


def step(title):
    print(f"\n== {title}")


step("0. baseline, recorded")
cleanup_needed = False
try:
    run("mdp.drift", "--record")

    step("1. inject: PII table, expired exception still held, stray DELETE")
    cleanup_needed = True
    emails = ", ".join(f"('contact{i}@partner{i % 3}.com', '+1-415-555-{1000 + i}', 'follow up')" for i in range(12))
    sql("SYSADMIN", f"CREATE OR REPLACE TABLE {TABLE} (contact VARCHAR, phone VARCHAR, note VARCHAR)",
        f"INSERT INTO {TABLE} VALUES {emails}")
    sql("SECURITYADMIN", "GRANT ROLE FR_PII_READER TO USER MEI_CHEN",
        "GRANT DELETE ON TABLE CURATED.WORK.PROJECTS TO ROLE FR_DATA_ANALYST")

    step("2. drift --record: new problems alert")
    run("mdp.drift", "--record")

    step("3. drift --record again: same problems, no new alerts (dedup)")
    run("mdp.drift", "--record")

    step("4. remediate: drop table, revoke grants")
    cleanup()
    cleanup_needed = False

    step("5. drift --record: all three resolve")
    run("mdp.drift", "--record")
finally:
    if cleanup_needed:
        cleanup()
