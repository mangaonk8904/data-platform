"""One drift report over every control in the platform, with deduplicated alerts.

Checks (each yields Events with a severity and a stable fingerprint):
  grants      Phase 2: privileges held but not declared (HIGH), declared but missing (MEDIUM), orphan roles
  governance  Phase 3: coverage findings and missing/extra tags and policies
  classifier  Phase 5: sensitive-looking columns that are unclassified or classified too low
  exceptions  Phase 4: expired exceptions still held, additive roles held without an exception,
              exceptions expiring soon, FR_* roles held by users nobody manages
  hr (opt-in) Phase 4: users whose access differs from the HR feed

Plain reports are read-only. With --record, events go to GOVERNANCE.AUDIT.DRIFT_EVENTS and only
*changes* (newly opened, newly resolved) are reported as alerts, so a standing problem does not
re-alert on every run. Exit code reflects the worst open severity for CI/cron use.
"""
import argparse
import json
import os
import sys
import urllib.request
import uuid
from datetime import date
from typing import NamedTuple

from mdp.config import load
from mdp.sqlgen import SECURITYADMIN, SYSADMIN, _q

EVENTS_TABLE = "GOVERNANCE.AUDIT.DRIFT_EVENTS"
RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


class Event(NamedTuple):
    check: str
    severity: str
    fingerprint: str
    subject: str
    detail: str


def _ev(check, sev, key, subject, detail):
    return Event(check, sev, f"{check}:{key}", subject, detail)


# ---- pure converters -------------------------------------------------------------------------

def grant_events(to_add, to_revoke, orphans, missing_roles=()):
    from mdp.reconcile import statement
    out = [_ev("grants", "HIGH", f"extra:{a}", a.grantee, f"undeclared privilege held: {statement('REVOKE', a)}")
           for a in to_revoke]
    out += [_ev("grants", "MEDIUM", f"missing:{a}", a.grantee, f"declared privilege missing: {statement('GRANT', a)}")
            for a in to_add]
    out += [_ev("grants", "MEDIUM", f"orphan:{r}", r, "role looks managed but is not in access.yaml") for r in orphans]
    out += [_ev("grants", "HIGH", f"norole:{r}", r, "declared role does not exist") for r in missing_roles]
    return out


def governance_events(findings, to_add, to_remove, cfg):
    from mdp.governance import statement
    out = [_ev("governance", "HIGH", f"finding:{f}", f.split(":")[0], f) for f in findings]
    out += [_ev("governance", "HIGH", f"missing:{a}", a.target, f"protection missing: {statement('ADD', a, cfg)}")
            for a in to_add]
    out += [_ev("governance", "MEDIUM", f"extra:{a}", a.target, f"undeclared attachment: {statement('REMOVE', a, cfg)}")
             for a in to_remove]
    return out


def classifier_events(findings, unreadable=()):
    out = [_ev("classifier", f.severity, f"{f.kind}:{f.column}:{f.suggested}", f.column,
               f"{f.kind.lower().replace('_', ' ')}: looks like {f.suggested} (config: {f.current}, "
               f"conf {f.confidence:.2f}); {f.evidence}") for f in findings]
    out += [_ev("classifier", "LOW", f"unreadable:{t}", t, "table not readable by SYSADMIN, not scanned") for t in unreadable]
    return out


def exception_events(cfg, holders, managed, today):
    """holders: {user: set(FR roles it holds)} (every USER holding an FR role); managed: HR-managed users."""
    from mdp.hr_sync import username
    h, a = cfg.get("hr_sync", {}), cfg.get("alerts", {})
    allowed, warn = set(a.get("allowed_role_holders", [])), a.get("exception_warning_days", 14)
    exc = [(username(e["employee"]), e["role"], e["expires"], e["reason"]) for e in h.get("exceptions", [])]
    active = {(u, r) for u, r, exp, _ in exc if exp >= today}
    expired = {(u, r) for u, r, exp, _ in exc if exp < today}  # reported above if still held
    additive = {r for _, r, _, _ in exc}
    out = []
    for u, r, exp, why in exc:
        if exp < today and r in holders.get(u, ()):
            out.append(_ev("exceptions", "HIGH", f"expired:{u}:{r}", u, f"exception for {r} expired {exp} ({why}) but role is still held"))
        elif 0 <= (exp - today).days <= warn:
            out.append(_ev("exceptions", "LOW", f"expiring:{u}:{r}:{exp}", u, f"exception for {r} expires {exp} ({(exp - today).days} days)"))
    for u, roles in holders.items():
        if u in allowed:
            continue
        for r in sorted(roles & additive):
            if (u, r) not in active and (u, r) not in expired:
                out.append(_ev("exceptions", "HIGH", f"noexception:{u}:{r}", u, f"holds additive role {r} with no exception on record"))
        if u not in managed:
            out.append(_ev("exceptions", "HIGH", f"unmanaged:{u}", u, f"holds {', '.join(sorted(roles))} but is not an HR-managed user or allowed holder"))
    return out


def hr_events(changes):
    return [_ev("hr", "MEDIUM", f"{c.action}:{c.user}:{c.role}", c.user,
                f"access differs from HR feed: {c.action} {c.role} ({c.reason})".replace("  ", " ")) for c in changes]


def diff_events(current, open_fps):
    """-> (new events, resolved fingerprints). open_fps: fingerprints whose latest recorded status is OPEN."""
    cur = {e.fingerprint: e for e in current}
    new = [cur[f] for f in sorted(set(cur) - set(open_fps))]
    return sorted(new, key=lambda e: (RANK[e.severity], e.fingerprint)), sorted(set(open_fps) - set(cur))


def worst(events):
    return min((RANK[e.severity] for e in events), default=None)


def slack_payload(new, resolved):
    lines = [f"*Data platform drift*: {len(new)} new, {len(resolved)} resolved"]
    lines += [f"• [{e.severity}] {e.check}/{e.subject}: {e.detail}" for e in new[:20]]
    if len(new) > 20:
        lines.append(f"…and {len(new) - 20} more")
    lines += [f"• resolved {f}" for f in resolved[:10]]
    return {"text": "\n".join(lines)}


# ---- Snowflake I/O -------------------------------------------------------------------------------

def _rows(cur, sql):
    cur.execute(sql)
    cols = [d[0].lower() for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def read_holders(cfg, cur):
    holders = {}
    for role in cfg["functional_roles"]:
        for r in _rows(cur, f"SHOW GRANTS OF ROLE {role}"):
            if r["granted_to"] == "USER":
                holders.setdefault(r["grantee_name"], set()).add(role)
    return holders


EVENTS_DDL = (f"CREATE TABLE IF NOT EXISTS {EVENTS_TABLE} (run_id VARCHAR, ts TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(), "
              f"status VARCHAR, check_name VARCHAR, severity VARCHAR, fingerprint VARCHAR, subject VARCHAR, detail VARCHAR)")


def read_open(cur):
    cur.execute(EVENTS_DDL)
    return {r["fingerprint"] for r in _rows(cur, f"""
        SELECT fingerprint, status FROM {EVENTS_TABLE}
        QUALIFY ROW_NUMBER() OVER (PARTITION BY fingerprint ORDER BY ts DESC) = 1""") if r["status"] == "OPEN"}


def record(cur, run_id, new, resolved):
    rows = [(run_id, "OPEN", e.check, e.severity, e.fingerprint, e.subject, e.detail) for e in new]
    rows += [(run_id, "RESOLVED", f.split(":")[0], "", f, "", "no longer detected") for f in resolved]
    if rows:
        vals = ", ".join("(" + ", ".join(f"'{_q(x)}'" for x in r) + ")" for r in rows)
        cur.execute(f"INSERT INTO {EVENTS_TABLE} (run_id, status, check_name, severity, fingerprint, subject, detail) VALUES {vals}")


def collect(cfg, conn, today, hr_feed=None):
    from mdp import classify, governance, hr_sync, reconcile
    events = []
    to_add, to_revoke, orphans, missing = reconcile.plan(cfg, conn)
    events += grant_events(to_add, to_revoke, orphans, missing)
    cur = conn.cursor()
    cur.execute(f"USE ROLE {SYSADMIN}")
    cur.execute("USE SECONDARY ROLES NONE")
    findings, g_add, g_remove = governance.plan(cfg, cur)
    events += governance_events(findings, g_add, g_remove, cfg)
    cfindings, unreadable, _ = classify.scan(cfg, cur, cfg.get("alerts", {}).get("classifier_min_confidence", 0.6))
    events += classifier_events(cfindings, unreadable)
    cur.execute(f"USE ROLE {SECURITYADMIN}")
    current = hr_sync.read_current(cfg, cur)
    events += exception_events(cfg, read_holders(cfg, cur), set(current), today)
    if hr_feed:
        events += hr_events(hr_sync.plan(cfg, hr_sync.read_feed(hr_feed), current, today))
    return sorted(events, key=lambda e: (RANK[e.severity], e.check, e.fingerprint))


def main():
    ap = argparse.ArgumentParser(description="Report (and optionally record/alert on) drift across all controls")
    ap.add_argument("--record", action="store_true", help="persist events; report only what changed since last run")
    ap.add_argument("--hr-feed", help="also compare user access with this HR feed")
    ap.add_argument("--fail-on", choices=["high", "medium", "low"], help="exit 2 if any open event is at least this severe")
    ap.add_argument("--as-of", help="YYYY-MM-DD, default today")
    ap.add_argument("--config")
    args = ap.parse_args()
    cfg, today = load(args.config), date.fromisoformat(args.as_of) if args.as_of else date.today()

    from mdp.conn import connect
    with connect(role=SECURITYADMIN) as conn:
        events = collect(cfg, conn, today, args.hr_feed)
        for e in events:
            print(f"{e.severity:6} {e.check:11} {e.subject:40} {e.detail}")
        print(f"-- {len(events)} open events "
              f"({sum(e.severity == 'HIGH' for e in events)} high, {sum(e.severity == 'MEDIUM' for e in events)} medium, "
              f"{sum(e.severity == 'LOW' for e in events)} low), as of {today}")
        if args.record:
            cur = conn.cursor()
            cur.execute(f"USE ROLE {SYSADMIN}")
            new, resolved = diff_events(events, read_open(cur))
            record(cur, str(uuid.uuid4()), new, resolved)
            print(f"-- recorded: {len(new)} newly opened, {len(resolved)} resolved, "
                  f"{len(events) - len(new)} unchanged (not re-alerted)")
            url = os.environ.get("ALERT_WEBHOOK_URL")
            if url and (new or resolved):
                req = urllib.request.Request(url, json.dumps(slack_payload(new, resolved)).encode(),
                                             {"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=10)
                print("-- webhook notified")
    if args.fail_on and (w := worst(events)) is not None and w <= RANK[args.fail_on.upper()]:
        sys.exit(2)


if __name__ == "__main__":
    main()
