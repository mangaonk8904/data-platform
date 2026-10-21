# CI/CD plan for the data platform

Status: **CI-0, CI-1 and CI-2 are implemented** (housekeeping, PR checks, CI identity and a read-only
plan workflow, section 12); the deploy and scheduled stages (CI-3 onward) are still a proposal. The deploy and scheduled workflows in sections 9.2
and 9.3 are drafts, not tested against GitHub or Snowflake. Section 13 lists what must be verified first.

Decisions made by the owner:

| Question | Decision | Consequence |
|---|---|---|
| Environments | **prod-only for now** (no dev account) | the deploy workflow has no `dev` job; `plan -> approve -> apply` on prod is the first time a change meets Snowflake, so the plan-hash approval gate carries the safety. `verify_*.py` stay out of CI until a dev account exists |
| Notifications | **GitHub issues and Slack** | drift failure opens/updates an issue and posts to `ALERT_WEBHOOK_URL` (a Slack incoming webhook); deploy failures do the same |

Audience: whoever owns this repo and will build and approve the pipeline.

## 1. Summary

This repo is *infrastructure as code for Snowflake access control*: a YAML file
([access.yaml](../config/access.yaml)) is rendered to SQL and reconciled against a live account.
CI/CD for it is not "build and ship an app". It is **"decide whether a change to who can see what is
safe, and apply it in the right order with a human in the loop for production."**

The pipeline has four parts:

| Part | Trigger | Touches Snowflake? | Purpose |
|---|---|---|---|
| **A. PR checks** | every pull request | no | tests, config validation, SQL diff, security scans; required to merge |
| **B. Deploy** | merge to `main` | yes: dev, then prod after approval | apply `access.yaml` in dependency order, verify, record drift |
| **C. Scheduled** | cron | yes | nightly drift detection; HR joiner/mover/leaver sync |
| **D. Break-glass** | a human, by hand | yes, as `ACCOUNTADMIN` | the few things automation must never hold the keys for |

Five rules shape everything below:

1. **CI never holds `ACCOUNTADMIN`.** The service identity has `SYSADMIN` + `SECURITYADMIN` only, the
   same narrowing Phase 2 enforced for `PLATFORM_ADMIN`.
2. **Code from a pull request never sees Snowflake credentials.** PR checks are fully offline.
3. **Production changes need a human approval** after that human has seen the exact plan.
4. **Deploys are idempotent and serialised**, so a failed or re-run deploy is safe and two never overlap.
5. **Everything that changes access leaves an audit trail** that ties back to a commit.

## 2. Where we are today

Facts from the repo as of commit `b2273ec`:

| Area | State |
|---|---|
| Workflows | one, [python-publish.yml](../.github/workflows/python-publish.yml): publishes to PyPI on release. It came from GitHub's template, was not written for this project, and does nothing useful here. **Delete it.** |
| Tests | 120 offline pytest tests, all green. They only run with `PYTHONPATH=src` because `pyproject.toml` has no build system or pytest config. |
| Branch protection / reviews | none. Anyone with write access can push to `main`. |
| `CODEOWNERS`, Dependabot | none |
| Environments | **one** Snowflake account, fixed database names (`RAW`, `CURATED`, ...). No dev/prod split anywhere in the code. The account is a trial (see `.env.example`), so it also expires. |
| Credentials | key-pair auth. [conn.py](../src/mdp/conn.py) reads a key *file* from `keys/rsa_key.p8` plus `SNOWFLAKE_*` env vars. Fine locally, awkward in CI. |
| Repo visibility | **public**. See section 4: this matters more than anything else in this document. |

Things in the code that are **dangerous to run unattended**, which the pipeline has to respect:

| Command | Hazard |
|---|---|
| `mdp.seed` | `TRUNCATE TABLE` on every business table on every run. Must never run in prod. |
| `mdp.reconcile --apply` | **revokes** any privilege not in the config. A bad merge removes access. |
| `mdp.hr_sync --apply` | disables users and revokes roles. Has a 25% blast-radius guard, but a feed bug under 25% still bites. |
| `mdp.governance --apply` | rewrites masking and row-policy bodies. A bad body can expose or hide data. |
| `mdp.narrow`, `governance --bootstrap-sql` | need `ACCOUNTADMIN`. Not CI material. |
| `scripts/verify_*.py`, `demo_*.py` | hard-code `USER = "PLATFORM_ADMIN"` and assert against seed data. Dev-only. |

## 3. Design principles

- **Declarative and reconciled, not scripted.** The repo already has a reconciler. CI's job is to run it
  safely, not to reimplement it. We are deliberately *not* introducing Terraform, schemachange or
  SnowDDL: they solve the same problem, but moving to them would discard Phases 2-5 (drift, tag-driven
  masking, HR sync, classifier) for no gain at this size. Revisit if the team grows or a Terraform
  estate already exists.
- **Plan, review, apply.** Every stage that can change access has a read-only `--plan` that CI shows to
  the reviewer before `--apply` runs.
- **Fail closed.** If a check cannot run, the deploy stops. A skipped security check is a failed one.
- **Separation of duties.** The person who writes a change is not the only person who approves it
  reaching production. Role design (`FR_*`, `AR_*`) is reviewed like application code.
- **Least privilege per job.** Each workflow declares `permissions:` explicitly (default `contents:
  read`), and each Snowflake-touching job gets its credentials from an *environment*, not the repo.

## 4. The public-repo problem (decide this first)

The repo is public. For a normal app that is fine. For this one it has three consequences:

1. **Workflow logs of public repos are public.** A deploy prints SQL: role names, grants, user names and
   emails, masking-policy bodies, schema layout. That is a map of your access model, published on every
   run. The seed/HR data is fake today; real HR feeds and real user lists would not be.
2. **Artifacts (saved plans) in a public repo are downloadable by anyone** who can see the repo.
3. **Secrets are safe from forks** (GitHub does not pass secrets to workflows triggered by fork PRs, and
   we will not use `pull_request_target`), but anyone with write access can exfiltrate them via a
   workflow change. Branch protection and required reviews are the real control, not secrecy.

Options:

| Option | Trade-off |
|---|---|
| **A. Make the repo private before wiring production** (recommended) | Logs and plans stop being public. Cost: environment protection rules (required reviewers) on private repos may need a paid GitHub plan; verify for your plan (section 13). |
| B. Stay public; deploy only to a throwaway/demo account | Fine for a portfolio piece: it is honestly a demo. Treat the Snowflake account as disposable and never connect real data or HR feeds. |
| C. Stay public, redact | Mask or suppress step output, never upload plans, post the plan only to an approver channel. Fragile: one `print` away from a leak. Not recommended. |

If this stays a portfolio/demo project (B), everything below still applies and is the right thing to
show; just keep real data out. If it will ever govern a real account, choose A.

## 5. Environments

Roles, users, resource monitors and warehouses are **account-level** objects in Snowflake. That is what
makes dev/prod separation here harder than for a normal app: you cannot give dev a separate `FR_FINANCE`
inside one account without renaming it.

| Option | How | Pros | Cons |
|---|---|---|---|
| **1. Two accounts: `dev` and `prod`** (recommended) | Same repo, same `access.yaml`, different `SNOWFLAKE_*` secrets per GitHub environment | Real isolation, zero code change to naming, dev can be wrecked safely, mirrors how teams run Snowflake | Second account to create/maintain; trial accounts expire |
| 2. One account, env prefix | add `environment:` to config and prefix every database/warehouse/role (`DEV_CURATED`, `AR_DEV_...`) | One account | Touches `sqlgen`, `reconcile`, `governance`, `hr_sync`, `drift`, tests; users and `ACCOUNTADMIN` are still shared; high risk of a prefix bug in the very code that guards access |
| 3. One account, no dev | PR checks offline; prod is the only target | Zero extra work | The first time a change meets real Snowflake is production. A masking-policy typo is found live |

Recommendation: **option 1**. Until a second account exists, run the pipeline against the single
account as "prod" with approval gates, and treat dev as not yet available (option 3). The workflows in
section 9 are written for two environments; deleting the `dev` job is a one-line change.

## 6. Identity and secrets

### 6.1 A dedicated CI identity

Create `CI_DEPLOYER`, separate from `PLATFORM_ADMIN` (which stays for humans working locally):

- key-pair auth only, no password, no MFA exemption needed because there is no password
- roles: `SYSADMIN` and `SECURITYADMIN` only; `DEFAULT_SECONDARY_ROLES = ()`; default warehouse `WH_ADMIN`
- its own key, so it can be revoked or rotated without touching anyone's laptop
- audit benefit: `GOVERNANCE.AUDIT.ACCESS_LOG.actor` is `CURRENT_USER()`, so CI runs and human runs are
  distinguishable

Add it to `platform_user` in the config (generalise it to a list) so its own grants are declared, and
create it once by hand as part of the break-glass bootstrap (section 7).

### 6.2 Secrets

Store in **GitHub environment secrets** (`dev`, `prod`), not repository secrets, so a PR job cannot read
them and each environment has its own key:

| Secret | Notes |
|---|---|
| `SNOWFLAKE_ACCOUNT` | secret, not variable: the identifier is sensitive in logs |
| `SNOWFLAKE_USER` | `CI_DEPLOYER` |
| `SNOWFLAKE_PRIVATE_KEY_B64` | base64 of the PKCS8 key; see 6.3 |
| `ALERT_WEBHOOK_URL` | optional, used by `mdp.drift --record` |

### 6.3 Code change: accept the key from the environment

[conn.py](../src/mdp/conn.py) only reads a key file. Add: if `SNOWFLAKE_PRIVATE_KEY_B64` is set, decode
it instead of reading `keys/rsa_key.p8`. That avoids writing a private key to the runner's disk. Keep
the file path as the fallback so local use is unchanged.

### 6.4 As built (CI-2)

- Config: `ci_user` in [access.yaml](../config/access.yaml), validated to hold only `SYSADMIN` and
  `SECURITYADMIN`.
- [ci_identity.py](../src/mdp/ci_identity.py): `python -m mdp.ci_identity --public-key-file keys/ci_deployer.pub`
  prints the SQL (default) or `--apply`s it. Re-running with a new key rotates the key. The user is
  `TYPE = SERVICE` (no password, no MFA); pass `--user-type ''` on an account without that option.
- [conn.py](../src/mdp/conn.py): `SNOWFLAKE_PRIVATE_KEY_B64` takes precedence over the key file.
- `SNOWFLAKE_ENV=prod` (set in every CI job) makes `mdp.seed` and the `demo_*` scripts refuse to run.
  The `verify_*`/`demo_*` scripts now grant roles to whoever is running them (`SNOWFLAKE_USER`).
- GitHub environment `prod-plan`, deployable from `main` only, with secrets `SNOWFLAKE_ACCOUNT`,
  `SNOWFLAKE_USER`, `SNOWFLAKE_PRIVATE_KEY_B64`.
- [plan.yml](../.github/workflows/plan.yml): manual, read-only. Prints the identity and its roles, then runs
  `reconcile --plan`, `governance --plan` and `drift --fail-on high`, failing on any drift.
- Tests ([test_workflows.py](../tests/test_workflows.py)) enforce that a workflow using Snowflake secrets is
  never PR-triggered, runs in an environment, runs only on `main`, sets `SNOWFLAKE_ENV=prod`, and shares the
  `snowflake-prod` concurrency group.

Key generation (the private key never goes through this repo's tooling):

```bash
openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt -out keys/ci_deployer.p8   # keys/ is gitignored
openssl rsa -in keys/ci_deployer.p8 -pubout -out keys/ci_deployer.pub
base64 < keys/ci_deployer.p8 | tr -d '\n' | gh secret set SNOWFLAKE_PRIVATE_KEY_B64 --env prod-plan
```

### 6.5 Hardening (later)

- **Network policy** on `CI_DEPLOYER` limiting logins to known egress IPs. GitHub-hosted runners use very
  large, changing IP ranges, so this only works with a self-hosted runner with a static address. **Never
  put a self-hosted runner on a public repo**: any fork PR could run code on it.
- **Keyless auth (OIDC / workload identity).** The goal is no long-lived key in GitHub at all. Snowflake
  has been adding workload-identity-federation support; whether it supports GitHub's OIDC issuer today is
  something to check in current Snowflake docs, not assume. Key-pair with rotation is the baseline.
- **Key rotation:** Snowflake supports two public keys per user (`RSA_PUBLIC_KEY` and `RSA_PUBLIC_KEY_2`),
  so rotate with no downtime: add key 2, update the GitHub secret, remove key 1. Calendar it every 90 days.

## 7. Part D: break-glass (stays manual, on purpose)

Automation must not hold `ACCOUNTADMIN`. These steps are run by a human, documented, and rare:

| Step | When | Command / SQL |
|---|---|---|
| ~~Create `CI_DEPLOYER` and register its public key~~ | **not break-glass after all**: `SECURITYADMIN` can create the user and grant it `SYSADMIN`/`SECURITYADMIN`, so `python -m mdp.ci_identity` does it with no `ACCOUNTADMIN` (verified live) | see 6.5 |
| Account-level `APPLY` grants for governance | once per account | `python -m mdp.governance --bootstrap-sql` |
| Resource monitors + attach to warehouses | once per account, and when a warehouse is added | `python -m mdp.narrow` (dry run first) |
| Rotate `ACCOUNTADMIN`-owned credentials | on schedule | Snowsight |

CI makes this safe by *detecting* the need rather than doing it: `governance --apply` already refuses to
run and prints the exact SQL when the `APPLY` grants are missing, and the deploy surfaces that message as
the job failure.

## 8. The pipelines

### 8.1 Part A: pull-request checks (no Snowflake, no secrets)

Required status checks on `main`. Nothing here needs a credential, so it is identical for forks.

| Job | What it does | Fails when |
|---|---|---|
| `test` | `uv sync --locked`, `pytest` (120 tests) | any test fails, or `uv.lock` is out of date |
| `config` | `load()` + `validate()` on `access.yaml`; `mdp.apply --dry-run` and `mdp.governance --dry-run` render all SQL | invalid config, unknown role/schema/warehouse, unrenderable SQL |
| `sql-diff` | render SQL on the base branch and on the PR, diff them, write the result to the job summary | never fails; it is for the reviewer: "this PR adds 14 statements and removes 2" |
| `lint` | `ruff check` and `ruff format --check` | style or obvious bugs |
| `security` | secret scan (gitleaks), `pip-audit` on `uv.lock`, CodeQL (free for public repos) | a committed key, a vulnerable dependency |
| `policy` | repo-specific guards (below) | a rule is broken |

**Policy guards** are small tests worth adding because they encode the platform's promises. Several
already exist as unit tests (`test_day_to_day_render_needs_no_accountadmin`,
`test_only_access_roles_get_object_privileges`); add the ones that guard the pipeline itself:

- no workflow file uses `pull_request_target` or references `secrets.` outside a deploy job
- every `uses:` in a workflow is pinned to a full commit SHA
- `render()` output never contains `ACCOUNTADMIN` outside `monitor_bootstrap` / `platform_user`

Why `sql-diff` matters: a one-line YAML change (`read: [CURATED.*]`) can render to dozens of grants. The
reviewer should approve the *effect*, not the diff of the input.

### 8.2 Part B: deploy on merge

Triggered by `push` to `main`. Serialised with `concurrency: group: deploy, cancel-in-progress: false`:
a second merge waits instead of overlapping, and an in-flight deploy is never cancelled half-way.

```
CI (part A, reused)
   └─► dev:   plan ─► apply ─► verify ─► drift check
           └─► prod: plan ─► [ human approval ] ─► apply ─► drift check
```

Stage order is fixed by dependencies between the tools, and is the same in every environment:

| # | Command | Why here | Safe to re-run? |
|---|---|---|---|
| 1 | `python -m mdp.apply` | creates databases, schemas, warehouses, access/functional/service roles. Additive only (`IF NOT EXISTS`) | yes |
| 2 | `python -m mdp.reconcile --plan`, then `--apply` | makes grants match; the only stage that **revokes** | yes |
| 3 | `python -m mdp.governance --apply` | tag, masking policies, row policy, entitlements. Needs tables to exist | yes |
| 4 | `python scripts/verify_access.py`, `verify_policies.py` | **dev only**: asserts per-role access against seed data | yes |
| 5 | `python -m mdp.drift --record --fail-on high` | confirms the end state has zero HIGH drift | yes |

`mdp.seed` is **never** part of the pipeline. It truncates tables. In dev it is a manual
`workflow_dispatch` job with a guard that refuses to run unless `SNOWFLAKE_ENV=dev`.

**Prod approval, done properly.** An approval is only meaningful if the approver saw what will run.
Two jobs:

1. `prod-plan` (no approval): runs `reconcile --plan`, `governance --plan`, `apply --dry-run`; writes the
   plan to the job summary and computes its SHA-256.
2. `prod-apply` (`environment: prod`, **required reviewers**): re-runs the same plans, **fails if the
   hash differs** from the one the reviewer approved, then applies.

The hash check closes the gap between "approved" and "applied": if someone drifted prod, or another
merge landed, the approver is asked again instead of silently approving something new.

**Rollback.** There is no `terraform destroy`; the repo is declarative, so rollback is `git revert` and
re-run the pipeline. What each stage does on revert:

| Stage | Revert behaviour |
|---|---|
| `apply` | does not drop anything (additive by design). A removed schema/role stays until a human drops it. Intentional: dropping is destructive |
| `reconcile` | re-grants what was revoked, revokes what was added |
| `governance` | policies are re-bodied (`SET BODY`), tags re-attached; never `CREATE OR REPLACE` |
| `hr_sync` | a wrongly disabled user is re-enabled by the next sync once the feed is right |

Anything not reversible by revert is listed in section 10 as a work item.

### 8.3 Part C: scheduled workflows

| Workflow | Cron (UTC) | Command | On failure |
|---|---|---|---|
| **Drift** | nightly | `mdp.drift --record --fail-on high` | open (or update) a GitHub issue; post to `ALERT_WEBHOOK_URL` |
| **HR sync** | daily, or hourly if the feed is live | `mdp.hr_sync <feed> --plan` then `--apply` | the 25% blast-radius guard aborts the run and alerts |

Notes specific to GitHub schedules:

- Scheduled workflows run only on the **default branch**, in **UTC**, and can be delayed by minutes under
  load. Do not rely on them for anything needing an exact time.
- In **public repos GitHub disables scheduled workflows after 60 days without repo activity.** A quiet
  governance repo is exactly the kind that hits this, and a silently disabled drift check is worse than
  none. Mitigate with a "heartbeat": the drift job fails loudly if the newest row in
  `GOVERNANCE.AUDIT.DRIFT_EVENTS` is older than 48 hours, and a separate external check (or a monthly
  calendar reminder) confirms the schedule still runs.
- HR sync is **data, not code**. It must not run on merge, and it needs its own trigger, secret and
  environment (`prod-hr`) so a feed problem cannot block an infrastructure deploy and vice versa.
  The feed today is a CSV committed in `data/`. In production the feed comes from the HR system (an API
  pull or a bucket) and **must never be committed**, especially to a public repo.

## 9. Draft workflow files

Drafts for review. `<sha>` placeholders mean "pin to the full commit SHA of the release shown in the
comment" (Dependabot can then keep them current). Not yet run.

### 9.1 `.github/workflows/ci.yml`

```yaml
name: CI
on:
  pull_request:
  workflow_call:          # reused by the deploy workflow

permissions:
  contents: read

concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>        # v4
      - uses: astral-sh/setup-uv@<sha>      # v5
        with: { enable-cache: true }
      - run: uv sync --locked
      - run: uv run pytest -q

  config:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - uses: astral-sh/setup-uv@<sha>
      - run: uv sync --locked
      - name: validate and render everything
        run: |
          uv run python -c "from mdp.config import load; load()"
          uv run python -m mdp.apply --dry-run > rendered.sql
          uv run python -m mdp.governance --dry-run >> rendered.sql
          wc -l rendered.sql

  sql-diff:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
        with: { fetch-depth: 0 }
      - uses: astral-sh/setup-uv@<sha>
      - run: uv sync --locked
      - name: render base and head, diff into the job summary
        run: |
          render() { uv run python -m mdp.apply --dry-run; uv run python -m mdp.governance --dry-run; }
          render > head.sql
          git checkout -q ${{ github.event.pull_request.base.sha }} -- config src
          render > base.sql || true
          git checkout -q ${{ github.sha }} -- config src
          { echo '### Rendered SQL diff'; echo '```diff'; diff -u base.sql head.sql || true; echo '```'; } >> "$GITHUB_STEP_SUMMARY"

  security:
    runs-on: ubuntu-latest
    permissions: { contents: read, security-events: write }
    steps:
      - uses: actions/checkout@<sha>
        with: { fetch-depth: 0 }
      - uses: gitleaks/gitleaks-action@<sha>   # v2
      - uses: astral-sh/setup-uv@<sha>
      - run: uvx pip-audit --requirement <(uv export --locked --no-hashes)
```

### 9.2 `.github/workflows/deploy.yml`

Draft written for two environments. **Per the prod-only decision, delete the `dev` job and make
`prod-plan` depend on `ci` directly.**

```yaml
name: Deploy
on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: deploy
  cancel-in-progress: false      # never kill a deploy half-way

jobs:
  ci:
    uses: ./.github/workflows/ci.yml

  dev:
    needs: ci
    runs-on: ubuntu-latest
    environment: dev
    env:
      SNOWFLAKE_ENV: dev
      SNOWFLAKE_ACCOUNT: ${{ secrets.SNOWFLAKE_ACCOUNT }}
      SNOWFLAKE_USER: ${{ secrets.SNOWFLAKE_USER }}
      SNOWFLAKE_PRIVATE_KEY_B64: ${{ secrets.SNOWFLAKE_PRIVATE_KEY_B64 }}
      SNOWFLAKE_WAREHOUSE: WH_ADMIN
    steps:
      - uses: actions/checkout@<sha>
      - uses: astral-sh/setup-uv@<sha>
      - run: uv sync --locked
      - run: uv run python -m mdp.apply
      - run: uv run python -m mdp.reconcile --apply
      - run: uv run python -m mdp.governance --apply
      - run: uv run python scripts/verify_access.py
      - run: uv run python scripts/verify_policies.py
      - run: uv run python -m mdp.drift --record --fail-on high

  prod-plan:
    needs: dev
    runs-on: ubuntu-latest
    environment: prod-plan         # no reviewers; read-only commands only
    env: { SNOWFLAKE_ENV: prod }   # + same SNOWFLAKE_* secrets, from prod-plan
    outputs:
      plan_sha: ${{ steps.plan.outputs.sha }}
    steps:
      - uses: actions/checkout@<sha>
      - uses: astral-sh/setup-uv@<sha>
      - run: uv sync --locked
      - id: plan
        run: |
          { uv run python -m mdp.reconcile --plan
            uv run python -m mdp.governance --plan
            uv run python -m mdp.apply --dry-run; } | tee plan.txt
          echo "sha=$(sha256sum plan.txt | cut -d' ' -f1)" >> "$GITHUB_OUTPUT"
          { echo '### Prod plan'; echo "sha256: \`$(sha256sum plan.txt | cut -d' ' -f1)\`"; echo '```'; cat plan.txt; echo '```'; } >> "$GITHUB_STEP_SUMMARY"

  prod-apply:
    needs: prod-plan
    runs-on: ubuntu-latest
    environment: prod              # required reviewers configured here
    env: { SNOWFLAKE_ENV: prod }   # + SNOWFLAKE_* secrets from prod
    steps:
      - uses: actions/checkout@<sha>
      - uses: astral-sh/setup-uv@<sha>
      - run: uv sync --locked
      - name: refuse if the plan changed since it was reviewed
        run: |
          { uv run python -m mdp.reconcile --plan
            uv run python -m mdp.governance --plan
            uv run python -m mdp.apply --dry-run; } > plan.txt
          test "$(sha256sum plan.txt | cut -d' ' -f1)" = "${{ needs.prod-plan.outputs.plan_sha }}"
      - run: uv run python -m mdp.apply
      - run: uv run python -m mdp.reconcile --apply
      - run: uv run python -m mdp.governance --apply
      - run: uv run python -m mdp.drift --record --fail-on high
```

The plan hash compares plan text that includes no timestamps, which holds today; if a future plan
format adds one, hash a normalised form instead.

### 9.3 `.github/workflows/scheduled.yml`

```yaml
name: Scheduled
on:
  schedule:
    - cron: "17 6 * * *"     # drift, nightly (off the :00 mark; GitHub is busiest on the hour)
  workflow_dispatch:

permissions:
  contents: read
  issues: write

jobs:
  drift:
    runs-on: ubuntu-latest
    environment: prod
    env: { SNOWFLAKE_ENV: prod }   # + SNOWFLAKE_* and ALERT_WEBHOOK_URL
    steps:
      - uses: actions/checkout@<sha>
      - uses: astral-sh/setup-uv@<sha>
      - run: uv sync --locked
      - run: uv run python -m mdp.drift --record --fail-on high
      - name: open an issue on failure
        if: failure()
        env: { GH_TOKEN: "${{ github.token }}" }
        run: gh issue create --title "Drift detected $(date -u +%F)" --body "See run ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}" --label drift
```

The HR-sync workflow is the same shape with its own environment, a step that fetches the feed to a
temporary file, `mdp.hr_sync "$FEED" --plan`, then `--apply`.

## 10. Code changes the pipeline needs

Ordered by how much they block. File links are where the change goes.

| # | Change | Why | Size |
|---|---|---|---|
| 1 | ~~`pyproject.toml`: pytest config, `dev` group, build system~~ **done in CI-0/1** (also fixed `python -m mdp.*` failing without `PYTHONPATH`) | tests and CLIs failed without `PYTHONPATH=src` | S |
| 2 | ~~[conn.py](../src/mdp/conn.py): `SNOWFLAKE_PRIVATE_KEY_B64`~~ **done** | no key file on runners (6.3) | S |
| 3 | ~~`scripts/verify_*.py`: take the user from `SNOWFLAKE_USER`, not the literal `PLATFORM_ADMIN`~~ **done** | otherwise they grant roles to the wrong user in CI | S |
| 4 | ~~[seed.py](../src/mdp/seed.py) and `demo_*.py`: refuse where `SNOWFLAKE_ENV=prod`~~ **done** | seed truncates tables; a mis-pointed secret must not be able to wipe prod | S |
| 5 | [reconcile.py](../src/mdp/reconcile.py): `--max-revokes N` guard, like HR sync's blast-radius check | a bad merge could revoke hundreds of grants in one run; today only a human reading the plan stops it | M |
| 6 | [governance.py](../src/mdp/governance.py): sync entitlements in one transaction (`DELETE` + `INSERT`, or `MERGE`) instead of `TRUNCATE` then `INSERT` | `TRUNCATE` auto-commits, so for a moment the row policy has no entitlements and denies everyone (fails closed, but it is an outage) | S |
| 7 | Machine-readable plans: `--format json` on the three `--plan` commands | better PR/issue comments, and a stable thing to hash | M |
| 8 | Record the deploy commit: add `deploy_sha` (from `GITHUB_SHA`) to `ACCESS_LOG` and `DRIFT_EVENTS` | ties every access change to the commit and run that made it | S |
| 9 | ~~Support more than one platform user~~ **done** as a separate `ci_user` section | declare `CI_DEPLOYER` alongside `PLATFORM_ADMIN` | M |
| 10 | Heartbeat check in `mdp.drift` (fail if last run > 48h) | schedules can be disabled silently (8.3) | S |

## 11. Repository controls

Set these in GitHub, in this order, **before** the deploy workflow exists:

1. **Branch protection / ruleset on `main`**: require pull requests, require the `test`, `config`,
   `security` checks, require branches to be up to date, block force-pushes and deletions. Apply to
   admins too.
2. **`CODEOWNERS`**: `config/access.yaml`, `src/mdp/sqlgen.py`, `reconcile.py`, `governance.py`,
   `hr_sync.py`, and `.github/` owned by a platform/security reviewer; require code-owner review. A
   masking-policy change should not merge on one author's say-so.
3. **Environments** `dev`, `prod-plan`, `prod`, `prod-hr`; `prod` gets required reviewers (not the
   author, if the plan allows "prevent self-review") and is limited to the `main` branch.
4. **Actions settings**: default workflow permissions read-only; require approval for first-time
   contributors' workflow runs; "Allow only actions from this repo and verified creators", plus SHA
   pinning in the workflows.
5. **Dependabot** for `github-actions` and `uv`/`pip`, weekly, so pinned SHAs and the lockfile stay
   current.
6. **Secret scanning and push protection** (free on public repos), and gitleaks in CI as a second net.
7. **Delete** `python-publish.yml`.

Supply chain, briefly: pin third-party actions to commit SHAs (a tag can be moved), `uv sync --locked`
so CI installs exactly the lockfile, keep the job `permissions` minimal, and never print secrets or run
`set -x` in a job that has them.

## 12. Rollout plan

Each step is independently useful and ends in something checkable.

| Step | Scope | Done when |
|---|---|---|
| **CI-0 Housekeeping** (done, except the GitHub settings) | delete the PyPI workflow; pytest config; Dependabot; CODEOWNERS; branch protection; decide repo visibility (4) | `main` rejects a direct push; `uv run pytest` passes with no env vars |
| **CI-1 PR checks** (done, not yet run on GitHub) | `ci.yml` (section 9.1) | a PR that breaks `access.yaml` or a test cannot merge; the SQL diff shows in the summary |
| **CI-2 CI identity** (done; plan workflow awaits first run) | create `CI_DEPLOYER` and key (break-glass); `conn.py` change; environment secrets; code changes 2-4 | a manual `workflow_dispatch` runs `reconcile --plan` against the account and prints "0 changes" |
| **CI-3 Gated deploy** | `deploy.yml` with dev (if a second account exists) and prod plan/approve/apply; code changes 5-8 | merging a one-line config change deploys it with one approval and the run proves zero drift afterwards |
| **CI-4 Scheduled** | nightly drift + issue on failure; HR sync workflow; heartbeat (change 10) | an injected drift (use `scripts/demo_alerts.py` in dev) opens an issue within a day |
| **CI-5 Hardening** | SHA pinning enforced by a policy test; evaluate keyless auth and network policy; key rotation drill; game-day | a deliberately bad PR, a revoked key, and a disabled schedule are each caught |

A sensible first milestone is **CI-0 + CI-1**: roughly an afternoon, no Snowflake credentials involved,
and it already gives you required tests, config validation and the SQL diff on every change.

**CI-0/1 as built:** `ci.yml` (jobs `test`, `lint`, `config`, `sql-diff`, `security`), `dependabot.yml`,
`CODEOWNERS`, ruff and pytest config, a build system so `mdp` is importable, and
[tests/test_workflows.py](../tests/test_workflows.py), which fails the build if a workflow uses
`pull_request_target`, an unpinned action, a non-`GITHUB_TOKEN` secret, or runs anything but the offline
renderers. Actions are pinned to the SHAs of the latest releases at the time of writing (checkout v7.0.1,
setup-uv v10.3.0, gitleaks-action v3.0.0); Dependabot keeps them current. The PyPI publish workflow is gone.

Still to do by hand in GitHub (not done by me, these are account settings): branch protection on `main`
with the `test`, `lint`, `config`, `security` checks required, and "Require review from Code Owners".

## 13. Verify before building

Things stated above from general knowledge that could be wrong or have changed. Check each against
current docs; none should be assumed.

- Required reviewers / protection rules for environments on **private** repos: which GitHub plan is
  needed.
- Whether Snowflake supports GitHub Actions OIDC for keyless login today (6.4).
- That `CREATE USER ... RSA_PUBLIC_KEY_2` rotation behaves as described on your edition.
- The exact scheduled-workflow inactivity rule (60 days) and that it applies to your repo.
- The latest release and full commit SHA to pin for each action in section 9.
- That `mdp.apply --dry-run`/`governance --dry-run` need no network, so the `config` job can run with no
  credentials (they import the Snowflake connector but do not connect; confirm in a clean runner).
- Whether the single trial account is acceptable as "prod" (it expires); otherwise create the second
  account first.

## 14. Failure modes

| Failure | What happens | Response |
|---|---|---|
| Deploy fails halfway (network, Snowflake error) | partial state; every stage is idempotent | fix the cause, re-run the same workflow; `drift` then confirms convergence |
| Approved plan no longer matches | `prod-apply` aborts on the hash check | re-review the new plan |
| Bad config merged | `reconcile` revokes legitimate access | users report; `git revert` + redeploy; guard 5 limits the radius |
| Masking-policy body wrong | data over- or under-exposed | revert and redeploy; `verify_policies` in dev should catch it first |
| `APPLY` grants missing | `governance --apply` stops and prints the SQL | a human runs the break-glass step (section 7) |
| Key leaked | attacker has `SYSADMIN` + `SECURITYADMIN` on the account | `ALTER USER CI_DEPLOYER UNSET RSA_PUBLIC_KEY`, rotate, review `ACCESS_LOG` and `QUERY_HISTORY` |
| Schedule silently disabled | no drift alerts | heartbeat check (change 10) |
| Two merges land together | second waits for the first | `concurrency` group, no cancel |
| Snowflake credit exhaustion | `WH_ADMIN` suspends at its monitor limit | deploy fails loudly; raise the quota via config (a normal PR) |

## 15. Decisions

Made: environments = prod-only for now; notifications = GitHub issues + Slack (see the top of this file).

Still open:

1. **Repo visibility** (section 4): make it private, or keep it public and treat the account as a
   disposable demo? Decide before CI-2, because that is when real credentials enter GitHub.
2. **Prod approver(s)**: who, and is self-approval allowed for a solo project?
3. **HR feed source** (8.3): where will the real feed come from, if ever?
