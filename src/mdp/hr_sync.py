"""Joiner / mover / leaver sync: make Snowflake users and their functional roles match an HR feed.

`plan` is a pure function (feed + config + current state -> ordered changes), so every rule is
unit-tested offline. Only users this tool created (COMMENT starts with MARK) are ever touched;
PLATFORM_ADMIN and any other user are invisible to it. Only FR_* roles are managed, service
roles and the admin roles are out of scope.

Rules
- active: user exists and is enabled, holds the roles of their job_family plus unexpired exceptions
- on_leave: disabled, roles kept so return is a one-line change
- terminated / past end_date / absent from the feed: disabled and every managed role revoked
- start_date in the future: ignored until the start date
- revokes and disables are ordered before grants and creates
- a run that would disable more than max_disable_fraction of users aborts (a truncated feed must
  not be able to lock everyone out); override with --force
Every change is written to GOVERNANCE.AUDIT.ACCESS_LOG with the run id, reason and employee id.
"""
import argparse
import csv
import re
import sys
import uuid
from datetime import date
from pathlib import Path
from typing import NamedTuple

from mdp.config import load
from mdp.sqlgen import SECURITYADMIN, SYSADMIN, _q

MARK = "managed-by=hr-sync"
AUDIT_TABLE = "GOVERNANCE.AUDIT.ACCESS_LOG"
LEAVER_STATUSES = {"terminated"}
FEED_COLUMNS = {"employee_id", "email", "full_name", "job_family", "status", "start_date", "end_date"}


class Change(NamedTuple):
    action: str      # CREATE_USER GRANT REVOKE DISABLE ENABLE
    user: str
    role: str        # '' unless GRANT/REVOKE
    reason: str
    employee_id: str


class SyncError(RuntimeError):
    pass


def username(email):
    return re.sub(r"[^A-Z0-9]+", "_", email.split("@")[0].upper()).strip("_")


def read_feed(path):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise SyncError(f"{path}: feed is empty; refusing to treat everyone as a leaver")
    missing = FEED_COLUMNS - set(rows[0])
    if missing:
        raise SyncError(f"{path}: missing columns {sorted(missing)}")
    return rows


def _day(s):
    return date.fromisoformat(s) if s else None


def desired(cfg, feed, today):
    """-> {user: {employee_id, email, name, roles:set, disabled:bool, leaver:bool}} for people who should exist."""
    h = cfg["hr_sync"]
    fr = set(cfg["functional_roles"])
    exc = {}
    for e in h.get("exceptions", []):
        if e["expires"] >= today:
            exc.setdefault(e["employee"].lower(), set()).add(e["role"])
    out = {}
    for r in feed:
        if _day(r["start_date"]) > today:
            continue  # pre-boarding: nothing until the start date
        family = r["job_family"]
        if family not in h["job_family_roles"]:
            raise SyncError(f"{r['employee_id']}: unknown job_family {family!r}; add it to hr_sync.job_family_roles")
        u = username(r["email"])
        if u in out:
            raise SyncError(f"username collision: {r['email']} and {out[u]['email']} both map to {u}")
        end = _day(r["end_date"])
        leaver = r["status"] in LEAVER_STATUSES or (end is not None and end <= today)
        on_leave = r["status"] == "on_leave"
        roles = set() if leaver else set(h["job_family_roles"][family]) | exc.get(r["email"].lower(), set())
        assert roles <= fr
        out[u] = dict(employee_id=r["employee_id"], email=r["email"], name=r["full_name"],
                      roles=roles, disabled=leaver or on_leave, leaver=leaver)
    return out


def plan(cfg, feed, current, today):
    """current: {user: {employee_id, disabled, roles:set}} for managed users. Returns ordered changes."""
    want = desired(cfg, feed, today)
    removals, additions = [], []
    for u, w in want.items():
        eid, have = w["employee_id"], current.get(u)
        if have is None:
            if w["leaver"]:
                continue  # never provisioned, nothing to remove
            additions.append(Change("CREATE_USER", u, "", "joiner", eid))
            additions += [Change("GRANT", u, r, "joiner", eid) for r in sorted(w["roles"])]
            if w["disabled"]:
                removals.append(Change("DISABLE", u, "", "on leave", eid))
            continue
        why = "leaver" if w["leaver"] else "access change"
        removals += [Change("REVOKE", u, r, why, eid) for r in sorted(have["roles"] - w["roles"])]
        additions += [Change("GRANT", u, r, why, eid) for r in sorted(w["roles"] - have["roles"])]
        if w["disabled"] and not have["disabled"]:
            removals.append(Change("DISABLE", u, "", "leaver" if w["leaver"] else "on leave", eid))
        elif have["disabled"] and not w["disabled"]:
            additions.insert(0, Change("ENABLE", u, "", "return", eid))
    for u, have in current.items():
        if u in want:
            continue
        removals += [Change("REVOKE", u, r, "absent from feed", have["employee_id"]) for r in sorted(have["roles"])]
        if not have["disabled"]:
            removals.append(Change("DISABLE", u, "", "absent from feed", have["employee_id"]))
    return removals + additions


def check_blast_radius(cfg, changes, current):
    disables = sum(c.action == "DISABLE" for c in changes)
    limit = cfg["hr_sync"]["max_disable_fraction"] * max(len(current), 1)
    if disables > limit:
        raise SyncError(f"would disable {disables} of {len(current)} managed users "
                        f"(limit {cfg['hr_sync']['max_disable_fraction']:.0%}); check the feed or pass --force")


def statement(c, email="", name=""):
    q = lambda s: _q(s)
    if c.action == "CREATE_USER":
        return (f"CREATE USER IF NOT EXISTS {c.user} LOGIN_NAME = '{q(email)}' EMAIL = '{q(email)}' "
                f"DISPLAY_NAME = '{q(name)}' DEFAULT_SECONDARY_ROLES = () "
                f"COMMENT = '{MARK}; employee={c.employee_id}'")
    if c.action in ("GRANT", "REVOKE"):
        return f"{c.action} ROLE {c.role} {'TO' if c.action == 'GRANT' else 'FROM'} USER {c.user}"
    return f"ALTER USER {c.user} SET DISABLED = {'TRUE' if c.action == 'DISABLE' else 'FALSE'}"


AUDIT_DDL = (f"CREATE TABLE IF NOT EXISTS {AUDIT_TABLE} (run_id VARCHAR, ts TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(), "
             f"action VARCHAR, target_user VARCHAR, role_name VARCHAR, reason VARCHAR, employee_id VARCHAR, "
             f"source VARCHAR, actor VARCHAR DEFAULT CURRENT_USER())")


def _rows(cur, sql):
    cur.execute(sql)
    cols = [d[0].lower() for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def read_current(cfg, cur):
    fr = set(cfg["functional_roles"])
    out = {}
    for r in _rows(cur, "SHOW USERS"):
        if not (r["comment"] or "").startswith(MARK):
            continue
        m = re.search(r"employee=(\S+)", r["comment"])
        grants = _rows(cur, f"SHOW GRANTS TO USER {r['name']}")
        out[r["name"]] = dict(employee_id=m.group(1) if m else "?",
                              disabled=str(r["disabled"]).lower() == "true",
                              roles={g["role"] for g in grants if g["role"] in fr})
    return out


def main():
    ap = argparse.ArgumentParser(description="Sync Snowflake users and functional roles from an HR feed")
    ap.add_argument("feed")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true", help="show changes, touch nothing (default)")
    mode.add_argument("--apply", action="store_true")
    ap.add_argument("--as-of", help="YYYY-MM-DD, default today (exceptions and start/end dates are judged on this)")
    ap.add_argument("--force", action="store_true", help="skip the blast-radius check")
    ap.add_argument("--config")
    args = ap.parse_args()
    cfg, today = load(args.config), _day(args.as_of) or date.today()
    feed = read_feed(args.feed)
    people = {username(r["email"]): r for r in feed}

    from mdp.conn import connect
    with connect(role=SECURITYADMIN) as conn:
        cur = conn.cursor()
        cur.execute("USE SECONDARY ROLES NONE")
        current = read_current(cfg, cur)
        changes = plan(cfg, feed, current, today)
        if not args.force:
            check_blast_radius(cfg, changes, current)
        for c in changes:
            print(f"{c.action:11} {c.user:14} {c.role:18} {c.reason:16} {c.employee_id}")
        print(f"-- plan: {len(changes)} changes for {len(feed)} employees ({len(current)} managed users today), as of {today}")
        if not args.apply or not changes:
            return
        run_id, source = str(uuid.uuid4()), Path(args.feed).name
        done = []
        try:
            for c in changes:
                p = people.get(c.user, {})
                cur.execute(statement(c, p.get("email", ""), p.get("full_name", "")))
                done.append(c)
        finally:  # whatever executed is audited, even if a later statement fails
            if done:
                cur.execute(f"USE ROLE {SYSADMIN}")
                cur.execute(AUDIT_DDL)
                vals = ", ".join(f"('{run_id}', '{c.action}', '{c.user}', '{c.role}', '{_q(c.reason)}', "
                                 f"'{c.employee_id}', '{source}')" for c in done)
                cur.execute(f"INSERT INTO {AUDIT_TABLE} (run_id, action, target_user, role_name, reason, "
                            f"employee_id, source) VALUES {vals}")
        audit = done
        print(f"-- applied {len(audit)} changes, audit run_id {run_id}")


if __name__ == "__main__":
    try:
        main()
    except SyncError as e:
        print(f"ABORT: {e}")
        sys.exit(1)
