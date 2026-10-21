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
