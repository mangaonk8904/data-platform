# Mercor Data Platform: Access Control & Governance

A governance-as-code system for a Snowflake warehouse modelled on a marketplace business
(experts, AI-lab customers, projects, tasks, payments). Built as interview prep for a Data
Platform Engineer role. Everything is declared in `config/access.yaml` and rendered into
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
src/mdp/seed.py        synthetic Mercor data
tests/                 offline unit tests for config and SQL generation
```

## Phases

0. Bootstrap, key-pair auth (done)
1. Layout, role hierarchy, warehouses, seed data (done)
2. Diffing reconciler with `--plan` and revoke of drift (this phase)
3. Tag-based masking, row access policies, per-role verification tests
4. Joiner/mover/leaver sync from a mock HR feed, with audit log
5. PII classifier and drift alerts
6. Access review report, cost attribution
7. Design doc, ADRs, Q&A sheet

## Running

```bash
cp .env.example .env            # fill in account/user; key in keys/
uv run python -m mdp.apply --dry-run     # print the SQL
uv run python -m mdp.apply               # apply
uv run python -m mdp.seed                # load synthetic data
uv run python -m mdp.reconcile --plan    # show drift (add --apply to fix, --fail-on-drift for CI)
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
