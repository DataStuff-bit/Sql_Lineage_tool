def extract_ctes(sql):
    import sqlglot
    from sqlglot import exp

    registry = {}

    try:
        parsed_list = sqlglot.parse(sql)
    except Exception:
        return {}

    for parsed in parsed_list:
        if not parsed:
            continue

        for cte in parsed.find_all(exp.CTE):
            name = cte.alias_or_name

            registry[name.lower()] = {
                "line": 0,
                "body": cte.this.sql() if cte.this else ""
            }

    return registry
