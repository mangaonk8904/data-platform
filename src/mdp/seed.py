"""Synthetic expert-marketplace data. Deterministic (seeded) so tests can assert on it."""
import random
from datetime import datetime, timedelta

from mdp.conn import connect

N_EXPERTS, N_PROJECTS, N_TASKS = 500, 40, 6000
DOMAINS = ["Law", "Medicine", "Finance", "Software", "Consulting", "Biology", "Physics", "Writing"]
COUNTRIES = ["US", "GB", "IN", "BR", "NG", "DE", "PH", "CA", "PL", "KE"]
FIRST = ["Ava", "Liam", "Noor", "Mateo", "Zoe", "Arjun", "Mei", "Omar", "Sofia", "Kofi", "Ines", "Ravi"]
LAST = ["Stone", "Patel", "Okafor", "Silva", "Novak", "Kim", "Haddad", "Rossi", "Chen", "Reyes"]
LABS = ["Orion Labs", "Helix AI", "Quanta Research", "Vector Minds", "Nimbus Models", "Atlas Intelligence",
        "Prism Systems", "Lumen AI"]

DDL = [
    ("CURATED.EXPERTS.EXPERTS", """expert_id NUMBER, email VARCHAR, full_name VARCHAR, country VARCHAR,
        domain VARCHAR, hourly_rate_usd NUMBER(8,2), status VARCHAR, signed_up_at TIMESTAMP_NTZ"""),
    ("CURATED.EXPERTS_SENSITIVE.EXPERT_PII", """expert_id NUMBER, tax_id VARCHAR, phone VARCHAR,
        street_address VARCHAR, date_of_birth DATE"""),
    ("CURATED.CUSTOMERS.CUSTOMERS", """customer_id NUMBER, name VARCHAR, tier VARCHAR,
        contract_value_usd NUMBER(12,2), region VARCHAR"""),
    ("CURATED.WORK.PROJECTS", """project_id NUMBER, customer_id NUMBER, name VARCHAR, domain VARCHAR,
        started_at TIMESTAMP_NTZ, status VARCHAR"""),
    ("CURATED.WORK.TASKS", """task_id NUMBER, project_id NUMBER, expert_id NUMBER, hours NUMBER(6,2),
        quality_score NUMBER(3,2), submitted_at TIMESTAMP_NTZ"""),
    ("CURATED.PAYMENTS.PAYMENTS", """payment_id NUMBER, expert_id NUMBER, task_id NUMBER,
        amount_usd NUMBER(10,2), paid_at TIMESTAMP_NTZ, method VARCHAR"""),
]


def generate(seed=7):
    rnd = random.Random(seed)
    base = datetime(2026, 1, 1)
    experts, pii = [], []
    for i in range(1, N_EXPERTS + 1):
        name = f"{rnd.choice(FIRST)} {rnd.choice(LAST)}"
        email = f"{name.lower().replace(' ', '.')}.{i}@example.com"
        experts.append((i, email, name, rnd.choice(COUNTRIES), rnd.choice(DOMAINS),
                        round(rnd.uniform(30, 250), 2), rnd.choice(["active"] * 8 + ["paused", "offboarded"]),
                        base + timedelta(days=rnd.randint(0, 250))))
        pii.append((i, f"{rnd.randint(100, 899)}-{rnd.randint(10, 99)}-{rnd.randint(1000, 9999)}",
                    f"+1-555-{rnd.randint(1000, 9999)}", f"{rnd.randint(1, 9999)} Example St",
                    datetime(1960, 1, 1).date() + timedelta(days=rnd.randint(0, 14000))))
    customers = [(i + 1, n, rnd.choice(["enterprise", "growth", "strategic"]),
                  round(rnd.uniform(5e5, 5e7), 2), ["NA", "EMEA", "APAC"][i % 3])  # every region present so row policies are testable
                 for i, n in enumerate(LABS)]
    projects = [(i, rnd.choice(customers)[0], f"Project {i:03d}", rnd.choice(DOMAINS),
                 base + timedelta(days=rnd.randint(0, 200)), rnd.choice(["active"] * 3 + ["completed"]))
                for i in range(1, N_PROJECTS + 1)]
    tasks, payments = [], []
    for t in range(1, N_TASKS + 1):
        e, p = rnd.choice(experts), rnd.choice(projects)
        hours = round(rnd.uniform(0.5, 12), 2)
        done = base + timedelta(days=rnd.randint(30, 290), hours=rnd.randint(0, 23))
        tasks.append((t, p[0], e[0], hours, round(rnd.uniform(0.3, 1.0), 2), done))
        payments.append((t, e[0], t, round(hours * float(e[5]), 2), done + timedelta(days=7),
                         rnd.choice(["bank", "paypal", "wise"])))
    return {"CURATED.EXPERTS.EXPERTS": experts, "CURATED.EXPERTS_SENSITIVE.EXPERT_PII": pii,
            "CURATED.CUSTOMERS.CUSTOMERS": customers, "CURATED.WORK.PROJECTS": projects,
            "CURATED.WORK.TASKS": tasks, "CURATED.PAYMENTS.PAYMENTS": payments}


def main():
    data = generate()
    with connect(role="SYSADMIN", warehouse="WH_ADMIN") as conn:
        cur = conn.cursor()
        for table, cols in DDL:
            cur.execute(f"CREATE TABLE IF NOT EXISTS {table} ({cols})")
            cur.execute(f"TRUNCATE TABLE {table}")
            rows = data[table]
            cur.executemany(f"INSERT INTO {table} VALUES ({', '.join(['%s'] * len(rows[0]))})", rows)
            print(f"{table}: {len(rows)} rows")


if __name__ == "__main__":
    main()
