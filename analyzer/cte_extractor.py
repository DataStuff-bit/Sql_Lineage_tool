def extract_ctes(sql):
    import sqlglot
    from sqlglot import exp

    registry = {}

    try:
        parsed = sqlglot.parse_one(sql, read="snowflake")
    except Exception as e:
        print("Parse error:", e)
        return {}

    if not parsed:
        return {}

    for cte in parsed.find_all(exp.CTE):
        alias = cte.alias
        name = alias.this if alias else None

        if not name:
            continue

        registry[name.lower()] = {
            "line": 0,
            "body": cte.this.sql(dialect="snowflake") if cte.this else ""
        }

    return registry
