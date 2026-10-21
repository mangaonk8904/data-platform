"""PII classifier: find sensitive columns nobody classified, or classified too low.

Phase 3 only enforces coverage in *restricted* schemas. This scans every table in every
layer and judges each column on two independent signals:
  - the column name (email, tax_id, phone, amount, ...), medium confidence
  - a sample of its values (email / phone / SSN / card+Luhn / IPv4 / IBAN shapes), high confidence
and compares the verdict with access.yaml. Detection is deterministic and explainable (each
finding carries its evidence); it needs no ML and no Snowflake classification licence.

Columns that are already masked are not re-judged by value (their sample is masked anyway);
they only matter if their configured class is GENERAL, which is the case worth flagging.
"""
import argparse
import re
import sys
from typing import NamedTuple

from mdp.config import column_classes, load

MIN_SAMPLES, MATCH_RATIO, SAMPLE_ROWS = 5, 0.6, 200
NAME_CONF, VALUE_CONF, BOTH_CONF = 0.7, 0.9, 0.97
SKIP_DATABASES = {"GOVERNANCE", "PLATFORM"}  # tooling state, not business data

# (class, label, regex on the lower-cased column name); first match wins, so order matters
NAME_RULES = [
    ("PII_DIRECT", "email", r"e_?mail"),
    ("PII_DIRECT", "person name", r"(^|_)(full|first|last|sur|given|display|legal)_?name($|_)"),
    ("PII_DIRECT", "ip address", r"(^|_)ip$|(^|_)ip_?addr"),
    ("PII_SENSITIVE", "government/tax id", r"(^|_)(ssn|sin|tin|tax_?id|national_?id|passport|driver_?licen[cs]e|social_?security)"),
    ("PII_SENSITIVE", "date of birth", r"(^|_)(dob|birth|date_?of_?birth)"),
    ("PII_SENSITIVE", "phone", r"(^|_)(phone|mobile|msisdn|cell|tel)($|_|number)"),
    ("PII_SENSITIVE", "postal address", r"(^|_)(street|address|postal|zip)(_?code)?($|_)"),
    ("PII_SENSITIVE", "bank/card", r"(^|_)(iban|routing|account_?number|card_?number|credit_?card|cvv|pan)($|_)"),
    ("FINANCIAL", "money", r"(salary|wage|compensation|hourly_?rate|rate_usd|amount|price|revenue|balance|payout|contract_value|invoice|_usd$)"),
]

EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
SSN = re.compile(r"^\d{3}-\d{2}-\d{4}$")
PHONE = re.compile(r"^(\+\d|\(\d{3}\)|\d{3}[ .-])[\d\s().-]{6,}$")
IPV4 = re.compile(r"^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$")
IBAN = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$")


def luhn(s):
    d = [int(c) for c in s[::-1]]
    return (sum(d[0::2]) + sum(sum(divmod(2 * x, 10)) for x in d[1::2])) % 10 == 0


def _card(v):
    digits = re.sub(r"[ -]", "", v)
    return digits.isdigit() and 13 <= len(digits) <= 19 and luhn(digits)


def _phone(v):
    return bool(PHONE.match(v)) and 7 <= len(re.sub(r"\D", "", v)) <= 15 and not SSN.match(v)


VALUE_RULES = [  # (class, label, predicate)
    ("PII_DIRECT", "email addresses", lambda v: bool(EMAIL.match(v))),
    ("PII_SENSITIVE", "SSN-shaped values", lambda v: bool(SSN.match(v))),
    ("PII_SENSITIVE", "payment card numbers (Luhn)", _card),
    ("PII_SENSITIVE", "phone numbers", _phone),
    ("PII_DIRECT", "IPv4 addresses", lambda v: bool(IPV4.match(v))),
    ("PII_SENSITIVE", "IBANs", lambda v: bool(IBAN.match(v))),
]


class Detection(NamedTuple):
    cls: str
    confidence: float
    evidence: str


class Finding(NamedTuple):
    severity: str   # HIGH | MEDIUM | LOW
    kind: str       # UNDER_CLASSIFIED | UNCLASSIFIED | DIFFERENT_CLASS
    column: str     # DB.SCHEMA.TABLE.COLUMN
    suggested: str
    current: str    # configured class or '-'
    confidence: float
    evidence: str


def by_name(name):
    n = name.lower()
    for cls, label, rx in NAME_RULES:
        if re.search(rx, n):
            return Detection(cls, NAME_CONF, f"column name looks like {label}")
    return None


def by_values(samples):
    vals = [v.strip() for v in samples if isinstance(v, str) and v.strip()]
    if len(vals) < MIN_SAMPLES:
        return None
    for cls, label, pred in VALUE_RULES:
        hits = sum(1 for v in vals if pred(v))
        if hits / len(vals) >= MATCH_RATIO:
            return Detection(cls, VALUE_CONF, f"{hits}/{len(vals)} sampled values are {label}")
    return None


def detect(name, samples=()):
    """Combine both signals. Agreement raises confidence; disagreement keeps the stronger (value) signal."""
    n, v = by_name(name), by_values(samples)
    if n and v:
        if n.cls == v.cls:
            return Detection(n.cls, BOTH_CONF, f"{n.evidence}; {v.evidence}")
        return v._replace(evidence=f"{v.evidence} (name suggested {n.cls})")
    return v or n


def judge(cfg, column, detection, min_conf=0.6):
    """Compare a detection with access.yaml. None means nothing to report."""
    if detection is None or detection.cls == "GENERAL" or detection.confidence < min_conf:
        return None
    current = column_classes(cfg).get(column)
    if current == detection.cls:
        return None
    if current is None:
        sev = "HIGH" if detection.confidence >= VALUE_CONF else "MEDIUM"
        return Finding(sev, "UNCLASSIFIED", column, detection.cls, "-", detection.confidence, detection.evidence)
    if current == "GENERAL":
        return Finding("HIGH", "UNDER_CLASSIFIED", column, detection.cls, current, detection.confidence, detection.evidence)
    return Finding("LOW", "DIFFERENT_CLASS", column, detection.cls, current, detection.confidence, detection.evidence)


def evaluate(cfg, tables, min_conf=0.6):
    """tables: {'DB.SCHEMA.TABLE': {COLUMN: [samples]}} -> findings, most severe first."""
    out = []
    for table, cols in tables.items():
        for col, samples in cols.items():
            f = judge(cfg, f"{table}.{col}", detect(col, samples), min_conf)
            if f:
                out.append(f)
    return sorted(out, key=lambda f: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}[f.severity], f.column))


def sample_tables(cfg, cur):
    """Read a small sample of every table outside the tooling databases. Returns (tables, unreadable)."""
    tables, unreadable = {}, []
    for db in cfg["databases"]:
        if db in SKIP_DATABASES:
            continue
        cur.execute(f"SHOW TABLES IN DATABASE {db}")
        cols = [d[0].lower() for d in cur.description]
        names = [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]
        for t in names:
            if t["schema_name"] == "INFORMATION_SCHEMA":
                continue
            fqn = f"{t['database_name']}.{t['schema_name']}.{t['name']}"
            try:
                cur.execute(f"SELECT * FROM {fqn} SAMPLE ({SAMPLE_ROWS} ROWS)")
                header = [d[0] for d in cur.description]
                rows = cur.fetchall()
            except Exception:
                unreadable.append(fqn)
                continue
            tables[fqn] = {h: [r[i] for r in rows] for i, h in enumerate(header)}
    return tables, unreadable


def scan(cfg, cur, min_conf=0.6):
    tables, unreadable = sample_tables(cfg, cur)
    return evaluate(cfg, tables, min_conf), unreadable, tables


def main():
    ap = argparse.ArgumentParser(description="Find unclassified or under-classified PII columns")
    ap.add_argument("--min-confidence", type=float)
    ap.add_argument("--fail-on-findings", action="store_true")
    ap.add_argument("--config")
    args = ap.parse_args()
    cfg = load(args.config)
    min_conf = args.min_confidence or cfg.get("alerts", {}).get("classifier_min_confidence", 0.6)

    from mdp.conn import connect
    with connect(role="SYSADMIN", warehouse="WH_ADMIN") as conn:
        cur = conn.cursor()
        cur.execute("USE SECONDARY ROLES NONE")
        findings, unreadable, tables = scan(cfg, cur, min_conf)
    for f in findings:
        print(f"{f.severity:6} {f.kind:16} {f.column:52} suggest {f.suggested:13} (config: {f.current}) "
              f"conf {f.confidence:.2f}: {f.evidence}")
    for t in unreadable:
        print(f"?      UNREADABLE       {t}: not readable by SYSADMIN, not scanned")
    ncols = sum(len(c) for c in tables.values())
    print(f"-- scanned {ncols} columns in {len(tables)} tables: {len(findings)} findings, {len(unreadable)} unreadable")
    if args.fail_on_findings and findings:
        sys.exit(2)


if __name__ == "__main__":
    main()
