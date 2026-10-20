from mdp.conn import connect

with connect() as c:
    cur = c.cursor()
    cur.execute("select current_user(), current_role(), current_region(), current_version()")
    print(cur.fetchone())
    cur.execute("show warehouses")
    print([(r[0], r[3], r[4]) for r in cur.fetchall()])
