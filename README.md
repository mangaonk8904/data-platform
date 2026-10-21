# Data Platform: Access Control & Governance

A governance-as-code system for a Snowflake warehouse modelled on a marketplace business
(experts, AI-lab customers, projects, tasks, payments). Everything is declared in `config/access.yaml` and rendered into
idempotent SQL; nothing is hand-granted.

## Problems this addresses

| Problem | Design response |
|---|---|
| No ownership; raw and curated data mixed | Layered databases, one schema per source/domain, owner + sensitivity recorded per schema |
| Over-broad grants, `ACCOUNTADMIN` sprawl | Three-tier role model, managed-access schemas, admin roles used only to bootstrap |
| Access doesn't follow people (joiners/movers/leavers) | Users hold *functional roles only*; membership is the only thing that changes (Phase 4) |
| PII everywhere | Sensitive columns isolated in their own schema now; tag-based masking in Phase 3 |
| Runaway spend, no attribution | One warehouse per workload, auto-suspend 60s, monthly resource monitors |
| Shared service credentials | One service role + warehouse per tool (Fivetran, Airflow, Hex), key-pair auth |

## Data layout

Databases are layers; schemas are sources (RAW) or domains (CURATED, MARTS).

```
RAW          landing zone, written by ingestion tools only. Never queried by humans.
  FIVETRAN_PG        operational Postgres replicated by Fivetran
  FIVETRAN_STRIPE    payouts data
  INTERNAL_UPLOADS   vendor files, one-off loads

CURATED      cleaned, modelled, owned. The source of truth.
  EXPERTS            expert profile (email/name tagged PII, masked for most roles)
  EXPERTS_SENSITIVE  tax id, phone, address, DOB. Restricted; separate schema so the
                     default answer to "can analysts see it?" is structurally no
  CUSTOMERS          AI-lab customers and contracts
  WORK               projects, tasks, submissions, quality scores
  PAYMENTS           expert payouts

MARTS        team-facing aggregates; what dashboards read
  GROWTH  FINANCE  ML  EXEC

GOVERNANCE   tags, masking/row-access policies, entitlement mapping, audit log
  TAGS  POLICIES  ENTITLEMENTS  AUDIT

PLATFORM     tooling state: pipeline health, cost attribution
  OPS  COST
```

Every schema is created `WITH MANAGED ACCESS`: object owners cannot grant on their own
objects. Only the schema owner (`SYSADMIN`) or a role with `MANAGE GRANTS` (`SECURITYADMIN`)
can, which keeps grant decisions centralised and auditable.

Snowflake auto-creates a `PUBLIC` schema in every new database. It is ungoverned, so the
generator drops it everywhere.

Each schema carries `owner_team` and `sensitivity` (`internal` / `confidential` /
`restricted`) in `access.yaml`; these become the schema `COMMENT` today and tags in Phase 3.

## Role model

```
User ──► Functional role (job)  ──► Access role (object+privilege) ──► Grants
         FR_DATA_ANALYST            AR_CURATED__WORK__RO                 USAGE, SELECT
         FR_FINANCE                 AR_MARTS__FINANCE__RW                + FUTURE tables/views
         SVC_AIRFLOW                AR_WH_TRANSFORM__USAGE               USAGE on warehouse
```

1. **Access roles** (`AR_<DB>__<SCHEMA>__<RO|RW>`, `AR_<WH>__USAGE`) are the only roles
   that hold privileges. Generated per schema and per warehouse, never edited by hand.
   - `RO`: `USAGE` on database and schema, `SELECT` on all and future tables/views.
   - `RW`: `RO` plus `INSERT/UPDATE/DELETE/TRUNCATE` on tables and `CREATE TABLE/VIEW`.
2. **Functional roles** (`FR_*`) map to jobs. They hold no privileges directly, only
   access roles. This is the only layer humans are granted.
3. **Service roles** (`SVC_*`) are the same shape, for tools. Each has its own warehouse
   so cost and failures are attributable, and key-pair auth only.

| Role | Reads | Writes | Warehouse |
|---|---|---|---|
| FR_DATA_ANALYST | CURATED.{WORK,CUSTOMERS,EXPERTS}, MARTS.{GROWTH,EXEC} | none | WH_ANALYTICS |
| FR_DATA_SCIENTIST | CURATED.{WORK,EXPERTS} | MARTS.ML | WH_ANALYTICS |
| FR_FINANCE | CURATED.{PAYMENTS,CUSTOMERS} | MARTS.FINANCE | WH_ANALYTICS |
| FR_SUPPORT | CURATED.{EXPERTS,WORK} | none | WH_ANALYTICS |
| FR_PII_READER | CURATED.EXPERTS_SENSITIVE | none | WH_ANALYTICS |
| FR_DATA_PLATFORM | GOVERNANCE.* | PLATFORM.* | WH_ADMIN |
| SVC_FIVETRAN | none | RAW.FIVETRAN_* | WH_LOADING |
| SVC_AIRFLOW | RAW.* | CURATED.*, MARTS.* | WH_TRANSFORM |
| SVC_HEX | MARTS.* | none | WH_ANALYTICS |

Design choices worth defending:
- **Platform engineers do not read data by default.** `FR_DATA_PLATFORM` manages policies
  and tooling; reading PII requires explicitly holding `FR_PII_READER`.
- **Hex reads MARTS only.** Dashboards can't bypass curation or leak PII, which is the
  Hex-governance point in the JD.
- **`FR_PII_READER` is additive**, not a superset role, so unmasking is a visible,
  separately-reviewable grant.
- **Roles are owned by `SECURITYADMIN`, objects by `SYSADMIN`.** Standard separation of
  duties; `ACCOUNTADMIN` is bootstrap only.
- `PLATFORM_ADMIN` (service user, key-pair) runs this tooling with `SYSADMIN` +
  `SECURITYADMIN` only: no `ACCOUNTADMIN`, no secondary roles (`platform_user` in
  `access.yaml`). Resource monitors are the one `ACCOUNTADMIN`-only job: the create privilege
  isn't grantable, and attaching a monitor to a warehouse needs `MODIFY` on the whole
  account. `python -m mdp.narrow --execute` does that once as `ACCOUNTADMIN` (create, hand
  ownership to `SYSADMIN`, attach), proves the narrowed roles can still alter quotas,
  and only then revokes `ACCOUNTADMIN`. Re-adding a warehouse needs the same break-glass step.

## Warehouses

| Warehouse | Used by | Size | Monthly credit cap |
|---|---|---|---|
| WH_ADMIN | platform tooling, seeding | XSMALL | 10 |
| WH_LOADING | Fivetran | XSMALL | 20 |
| WH_TRANSFORM | Airflow | XSMALL | 30 |
| WH_ANALYTICS | analysts, Hex | XSMALL | 20 |

All: `AUTO_SUSPEND=60`, `AUTO_RESUME`, `INITIALLY_SUSPENDED`. Each has a resource monitor
that notifies at 80% and suspends at 100%. Separate warehouses mean `QUERY_HISTORY` and
`WAREHOUSE_METERING_HISTORY` give cost attribution by workload with no tagging gymnastics.

## Repo layout

```
config/access.yaml     desired state (source of truth)
src/mdp/config.py      load + validate (unknown schemas/warehouses fail fast)
src/mdp/sqlgen.py      desired state -> ordered, idempotent SQL
src/mdp/apply.py       CLI: --dry-run prints SQL, otherwise executes it (additive)
src/mdp/narrow.py      one-time ACCOUNTADMIN bootstrap, then drops it from the service user
src/mdp/reconcile.py   CLI: diff declared vs actual grants; --plan (default) / --apply revokes drift
src/mdp/governance.py  tag-driven masking + row access policies: apply, plan, coverage checks
src/mdp/hr_sync.py     HR feed -> Snowflake users + functional roles, with audit log
src/mdp/classify.py    PII classifier: column names + sampled values vs access.yaml
src/mdp/drift.py       one drift report over every control; deduplicated alert log
src/mdp/seed.py        synthetic data
data/hr_feed_*.csv     mock HR feed: day 1, and day 2 with a joiner, mover, leaver and leave
tests/                 offline unit tests for config and SQL generation
```

## Phases

0. Bootstrap, key-pair auth (done)
1. Layout, role hierarchy, warehouses, seed data (done)
2. Diffing reconciler with `--plan` and revoke of drift (done)
3. Tag-based masking, row access policies, per-role verification tests (done)
4. Joiner/mover/leaver sync from a mock HR feed, with audit log (done)
5. PII classifier and drift alerts (this phase)
6. Access review report, cost attribution
7. Design doc, ADRs, Q&A sheet

## Running

```bash
cp .env.example .env            # fill in account/user; key in keys/
uv run python -m mdp.apply --dry-run     # print the SQL
uv run python -m mdp.apply               # apply
uv run python -m mdp.seed                # load synthetic data
uv run python -m mdp.reconcile --plan    # show drift (add --apply to fix, --fail-on-drift for CI)
uv run python -m mdp.governance --apply  # tags, masking + row policies (needs the bootstrap below once)
uv run python -m mdp.hr_sync data/hr_feed_day1.csv --apply   # --plan to preview; day2 for movers/leavers
uv run python -m mdp.classify            # find unclassified / under-classified PII anywhere
uv run python -m mdp.drift --record      # all checks; alert only on changes (cron this)
uv run python scripts/demo_alerts.py     # inject 3 problems, watch them alert once, fix, resolve
uv run python scripts/verify_policies.py # live: what each role actually sees (25 checks)
uv run python scripts/demo_drift.py      # inject rogue grants, catch and remove them
uv run --with pytest pytest
```

`scripts/verify_access.py` is the live proof: for each role it runs the same probes and
asserts which tables are readable or denied (17 checks). Writing it caught a real trap:
`PLATFORM_ADMIN` has `ACCOUNTADMIN` as a *secondary* role, which silently stays active
after `USE ROLE`, so every role looked like it could read everything. Tests must run
`USE SECONDARY ROLES NONE`. The same applies to any user with `DEFAULT_SECONDARY_ROLES=ALL`.

## Reconciler (Phase 2)

`mdp.apply` only adds. `mdp.reconcile` makes Snowflake match `access.yaml` in both
directions. It reads `SHOW GRANTS TO ROLE` and `SHOW FUTURE GRANTS TO ROLE` for every
managed role, expands declared grants into object-level atoms (`ALL TABLES IN SCHEMA`
against the tables that exist), and diffs the two sets. `sqlgen` and the reconciler share
one list of declared `Grant`s, so what gets applied and what gets checked cannot diverge.

- Managed roles (access, functional, service) are fully declarative: any privilege they hold
  that the config doesn't declare is revoked, on any object. `OWNERSHIP` is ignored.
- Roles that look managed (`AR_`/`FR_`/`SVC_`) but aren't in the config are reported, never touched.
- Grants to other roles (SYSADMIN, etc.) and users' role memberships are out of scope.
- Not yet reconciled: schema managed-access flag, warehouse settings, resource monitors.

`scripts/demo_drift.py` hand-grants the PII access role to the analyst role plus a stray
`DELETE`, shows an analyst really reading 500 PII rows, then reconciles and shows the
read denied and the plan empty.

## Masking and row access (Phase 3)

One tag, `GOVERNANCE.TAGS.DATA_CLASS`, is set on columns; one masking policy per data type
(string, number, date) is attached to the tag. The policy body switches on the tag value and
`IS_ROLE_IN_SESSION`, so protecting a column is a single tagging step in `access.yaml`.

| Class | Columns (examples) | Sees real values | Everyone else sees |
|---|---|---|---|
| PII_DIRECT | expert email, full_name | FR_SUPPORT, FR_PII_READER, SVC_AIRFLOW | `***MASKED***` |
| PII_SENSITIVE | tax_id, phone, address, DOB | FR_PII_READER, SVC_AIRFLOW | masked / NULL |
| FINANCIAL | hourly rate, payment amount, contract value | FR_FINANCE, SVC_AIRFLOW | NULL |
| GENERAL | everything else | everyone | n/a (declared, not tagged) |

Row access on `CURATED.CUSTOMERS` (Snowflake has no tag-based row policies): FR_FINANCE and
SVC_AIRFLOW see all rows, FR_DATA_ANALYST sees NA and EMEA, any other role sees none. The
role-to-region map lives in `GOVERNANCE.ENTITLEMENTS.REGION_ACCESS`, synced from config on every apply.

`mdp.governance --plan` diffs tag-on-column, policy-on-tag and policy-on-table against live
state and runs **coverage checks** that fail the plan: an unclassified column or table in a
restricted schema, a classified column whose type no policy covers, or a config column that no
longer exists. `--fail-on-drift` makes it a CI gate. Defining policies uses `CREATE ... IF NOT
EXISTS` then `SET BODY`, never `CREATE OR REPLACE`, which fails or detaches while attached.

Things learned the hard way:
- **One-time bootstrap.** `APPLY TAG / MASKING POLICY / ROW ACCESS POLICY ON ACCOUNT` can only be
  granted by `ACCOUNTADMIN` (SECURITYADMIN is refused). `--bootstrap-sql` prints the three grants;
  `--apply` checks for them first. After that SYSADMIN alone runs everything.
- **A masked column cannot be a row-policy argument.** Tagging `REGION` with a masking class made
  the whole table unreadable even though the plan was clean. Classes with `mask: false` are
  therefore declared (for coverage) but never tagged, and config validation rejects a masked
  row-policy column. Only `verify_policies.py`, which actually queries as each role, caught this.
- Seed customers now cycle through all regions, otherwise the APAC filter has nothing to hide.

## Joiners, movers, leavers (Phase 4)

Access follows people: `mdp.hr_sync` reads an HR feed (CSV here, an API in real life) and
makes Snowflake users and their `FR_*` roles match it. Nobody is granted a role by hand.

| Feed says | Snowflake does |
|---|---|
| new, `active`, start date reached | create user (no password, key/SSO only, no secondary roles), grant roles of their `job_family` |
| `job_family` changed | revoke old roles, grant new ones |
| `on_leave` | disable user, keep roles so return is one change |
| `terminated`, end date passed, or missing from the feed | revoke every managed role, disable user (kept, not dropped, for audit) |
| start date in the future | nothing yet |

`job_family -> roles` and **time-boxed exceptions** live in `access.yaml` (`hr_sync`). An
additive role like `FR_PII_READER` is only reachable through an exception that has a reason
and an expiry date; when it lapses the next sync revokes it. A role granted by hand outside
the feed is revoked as drift, same as Phase 2 does for roles.

Safety properties:
- **Only users it created are touched** (`COMMENT = 'managed-by=hr-sync; employee=...'`).
  `PLATFORM_ADMIN` and every other user are invisible to it.
- **Blast-radius limit**: a run that would disable more than `max_disable_fraction` (25%) of
  managed users aborts, so a truncated or empty feed cannot lock the company out.
  Verified live: a 3-row feed against 11 users is refused. `--force` overrides.
- **Revokes before grants**, so a mover never briefly holds both sets.
- **Least privilege**: runs as `SECURITYADMIN` (user and grant management) plus `SYSADMIN`
  for the audit write. No new account-level grants or `ACCOUNTADMIN` step.
- The decision logic (`plan`) is a pure function, covered by 18 offline tests.

Every change is appended to `GOVERNANCE.AUDIT.ACCESS_LOG` (run id, timestamp, action, user,
role, reason, employee id, source file, actor). Changes that executed are audited even if a
later statement in the same run fails.

Live demo result: day 1 created 10 users with 20 changes and re-plans empty (idempotent). Day 2
(7 changes) onboarded a joiner, moved a user from analyst to data scientist, disabled a leaver
and revoked their role, and put a user on leave; the grant reconciler and governance plan both
still show zero drift.

Known limits: users have no credentials yet (real onboarding needs SSO/SCIM or key registration);
within one run all audit rows share a timestamp, so intra-run order is not recorded.

## PII classifier and drift alerts (Phase 5)

**Classifier** (`mdp.classify`). Phase 3 enforces classification only in *restricted* schemas;
a new table of emails in an "internal" schema would sail through. The classifier samples
every table outside `GOVERNANCE`/`PLATFORM` and judges each column on two independent signals:
its **name** (email, tax_id, phone, amount, ...; 0.70 confidence) and its **values**
(email, phone, SSN, Luhn-valid card, IPv4, IBAN shapes in at least 60% of at least 5 samples;
0.90 confidence). Agreement gives 0.97; if they disagree the value signal wins. It is
deterministic and every finding carries its evidence ("12/12 sampled values are email addresses").

| Finding | Meaning | Severity |
|---|---|---|
| UNCLASSIFIED | looks sensitive, not in `governance.columns` | HIGH if value-confirmed, else MEDIUM |
| UNDER_CLASSIFIED | explicitly `GENERAL` but looks sensitive | HIGH |
| DIFFERENT_CLASS | classified, but as a different class than detected | LOW |

Already-masked columns are not re-read by value (their sample is masked), so the classifier
needs no PII access of its own. Unreadable tables are reported, not silently skipped.

**Drift monitor** (`mdp.drift`). One report over every control, each event with a severity and
a stable fingerprint:

| Check | Raises |
|---|---|
| grants (Phase 2) | undeclared privilege held (HIGH), declared one missing / orphan role (MEDIUM) |
| governance (Phase 3) | coverage findings, missing tag or policy (HIGH), extra attachment (MEDIUM) |
| classifier | the findings above |
| exceptions (Phase 4) | expired exception still held (HIGH), additive role with no exception (HIGH), `FR_*` held by an unmanaged user (HIGH), exception expiring within 14 days (LOW) |
| hr (`--hr-feed`) | user access differs from the feed (MEDIUM) |

With `--record`, events go to `GOVERNANCE.AUDIT.DRIFT_EVENTS` and only **changes** are alerts:
newly opened and newly resolved. A standing problem is not re-reported every run, and a problem
that returns after being fixed alerts again. `--fail-on high|medium|low` sets the exit code for
CI/cron; set `ALERT_WEBHOOK_URL` for a Slack-style JSON post (off by default, not exercised live).

`scripts/demo_alerts.py` is the live proof: it injects a table of emails and phones in
`CURATED.WORK`, an expired PII exception that was never revoked, and a stray `DELETE` grant;
the first run opens 4 alerts, the second opens none, and after remediation all 4 resolve.

Limits: the classifier samples 200 rows, so rare PII in a mostly-clean column can be missed;
it knows shapes, not free text or names of people in a plain `notes` column. Alert delivery is
a webhook only, and nothing schedules the run yet.
