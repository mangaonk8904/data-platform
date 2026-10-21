"""Guards for the pipeline itself: the workflows are security-sensitive code too."""
import re

import pytest
import yaml

from mdp.config import ROOT, load
from mdp.sqlgen import render

WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)", re.M)


def test_there_are_workflows():
    assert WORKFLOWS


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_workflows_are_valid_yaml_with_least_privilege(path):
    wf = yaml.safe_load(path.read_text())
    assert wf["permissions"], f"{path.name}: declare top-level permissions"
    assert wf["permissions"].get("contents") in ("read", None) or wf["permissions"] == {}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_full_sha(path):
    for ref in USES.findall(path.read_text()):
        if ref.startswith("./"):
            continue  # local reusable workflow
        assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", ref), f"{path.name}: {ref} is not pinned to a commit SHA"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_pull_request_target(path):
    assert "pull_request_target" not in path.read_text()


def test_pr_workflow_uses_no_secrets_except_the_github_token():
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert set(re.findall(r"secrets\.(\w+)", text)) <= {"GITHUB_TOKEN"}


def test_ci_never_touches_snowflake():
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "SNOWFLAKE_" not in text
    # the only mdp commands CI may run are the offline renderers
    for cmd in re.findall(r"python -m (mdp\.\w+)([^\n]*)", text):
        assert cmd[0] in ("mdp.apply", "mdp.governance") and "--dry-run" in cmd[1], cmd


def test_rendered_sql_contains_no_accountadmin_outside_bootstrap():
    assert all(role != "ACCOUNTADMIN" for role, _ in render(load()))


def _snowflake_workflows():
    return [p for p in WORKFLOWS if "secrets.SNOWFLAKE_" in p.read_text()]


def test_snowflake_workflows_exist_and_are_never_pr_triggered():
    assert _snowflake_workflows()
    for path in _snowflake_workflows():
        wf = yaml.safe_load(path.read_text())
        triggers = wf.get(True) or wf.get("on")     # PyYAML reads the key `on` as boolean True
        assert not ({"pull_request", "pull_request_target"} & set(triggers)), f"{path.name}: secrets in a PR workflow"
        assert set(triggers) <= {"workflow_dispatch", "schedule", "push", "workflow_call"}, path.name


def test_snowflake_jobs_use_a_protected_environment_and_run_only_on_main():
    for path in _snowflake_workflows():
        for name, job in yaml.safe_load(path.read_text())["jobs"].items():
            if "secrets.SNOWFLAKE_" in yaml.safe_dump(job):
                assert job.get("environment"), f"{path.name}:{name} has no environment"
                assert "refs/heads/main" in str(job.get("if", "")) or "push" in str(yaml.safe_load(path.read_text()).get(True)), \
                    f"{path.name}:{name} must be restricted to main"
                assert job["env"]["SNOWFLAKE_ENV"] == "prod"      # arms the seed/demo guards


def test_plan_workflow_is_read_only():
    text = (ROOT / ".github" / "workflows" / "plan.yml").read_text()
    assert "--apply" not in text and "--record" not in text
    assert "workflow_dispatch" in text


def test_snowflake_workflows_share_one_concurrency_group():
    for path in _snowflake_workflows():
        wf = yaml.safe_load(path.read_text())
        assert wf["concurrency"]["group"] == "snowflake-prod" and wf["concurrency"]["cancel-in-progress"] is False


def test_plan_identity_check_asserts_the_exact_role_set():
    text = (ROOT / ".github" / "workflows" / "plan.yml").read_text()
    assert '["role"]' in text and 'set(roles) == {"SYSADMIN", "SECURITYADMIN"}' in text
