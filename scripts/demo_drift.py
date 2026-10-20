"""Live demo: hand-grant rogue privileges, watch the reconciler catch and remove them.
Injects drift as SECURITYADMIN (like an engineer fixing something 'just this once'),
proves the leak with a real query as FR_DATA_ANALYST, then reconciles and proves it is closed."""
import warnings

from mdp.config import load
from mdp.conn import connect
from mdp.reconcile import plan, statement

warnings.filterwarnings("ignore")
USER = "PLATFORM_ADMIN"
ROGUE = [
    "GRANT ROLE AR_CURATED__EXPERTS_SENSITIVE__RO TO ROLE FR_DATA_ANALYST",
    "GRANT DELETE ON TABLE CURATED.WORK.TASKS TO ROLE AR_CURATED__WORK__RO",
]


def analyst_can_read_pii(cur):
    cur.execute("GRANT ROLE FR_DATA_ANALYST TO USER " + USER)
    try:
        cur.execute("USE ROLE FR_DATA_ANALYST")
        cur.execute("USE SECONDARY ROLES NONE")
        cur.execute("USE WAREHOUSE WH_ANALYTICS")
        try:
            cur.execute("SELECT COUNT(*) FROM CURATED.EXPERTS_SENSITIVE.EXPERT_PII")
            return cur.fetchone()[0]
        except Exception:
            return None
    finally:
        cur.execute("USE ROLE SECURITYADMIN")
        cur.execute("REVOKE ROLE FR_DATA_ANALYST FROM USER " + USER)


def show(conn, cfg):
    to_add, to_revoke, orphans, _ = plan(cfg, conn)
    for a in to_add:
        print(f"  + {statement('GRANT', a)}")
    for a in to_revoke:
        print(f"  - {statement('REVOKE', a)}")
    print(f"  = {len(to_add)} to grant, {len(to_revoke)} to revoke")
    return to_add, to_revoke


cfg = load()
with connect(role="SECURITYADMIN") as conn:
    cur = conn.cursor()
    print("1. baseline plan");              show(conn, cfg)
    print("2. injecting rogue grants")
    for sql in ROGUE:
        cur.execute("USE ROLE SECURITYADMIN"); cur.execute(sql); print("  !", sql)
    try:
        print("3. plan after drift");         show(conn, cfg)
        print("   analyst reads PII rows:", analyst_can_read_pii(cur), "(leak)")
    finally:
        print("4. reconciling")
        to_add, to_revoke, *_ = plan(cfg, conn)
        cur.execute("USE ROLE SECURITYADMIN")
        for a in to_add:
            cur.execute(statement("GRANT", a))
        for a in to_revoke:
            cur.execute(statement("REVOKE", a)); print("  revoked:", statement("REVOKE", a))
    print("5. plan after reconcile");       show(conn, cfg)
    print("   analyst reads PII rows:", analyst_can_read_pii(cur), "(None = denied)")
