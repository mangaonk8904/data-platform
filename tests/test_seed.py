from mdp.seed import N_EXPERTS, N_TASKS, generate


def test_deterministic():
    assert generate() == generate()


def test_referential_integrity():
    d = generate()
    experts = {r[0] for r in d["CURATED.EXPERTS.EXPERTS"]}
    projects = {r[0] for r in d["CURATED.WORK.PROJECTS"]}
    customers = {r[0] for r in d["CURATED.CUSTOMERS.CUSTOMERS"]}
    assert {r[0] for r in d["CURATED.EXPERTS_SENSITIVE.EXPERT_PII"]} == experts
    assert all(t[1] in projects and t[2] in experts for t in d["CURATED.WORK.TASKS"])
    assert all(p[1] in customers for p in d["CURATED.WORK.PROJECTS"])
    assert len(d["CURATED.PAYMENTS.PAYMENTS"]) == N_TASKS and len(experts) == N_EXPERTS
