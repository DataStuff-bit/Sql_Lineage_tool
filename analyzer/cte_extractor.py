def extract_ctes(sql: str):
    import sqlglot
    from sqlglot import exp
    import re

    registry = {}

    # -----------------------------
    # 1. Try parsing with Snowflake dialect
    # -----------------------------
    try:
        parsed = sqlglot.parse_one(sql, read="snowflake")
    except Exception as e:
        print("⚠️ Parse Error:", e)
        parsed = None

    # -----------------------------
    # 2. Extract CTEs using parser
    # -----------------------------
    if parsed:
        try:
            for cte in parsed.find_all(exp.CTE):
                alias = cte.alias
                name = alias.this if alias else None

                if not name:
                    continue

                registry[name.lower()] = {
                    "line": 0,
                    "body": cte.this.sql(dialect="snowflake") if cte.this else ""
                }
        except Exception as e:
            print("⚠️ CTE extraction error:", e)

    # -----------------------------
    # 3. Fallback (regex) if parser fails
    # -----------------------------
    if not registry:
        print("⚠️ Falling back to regex extraction...")

        # Handles multiple CTEs: WITH a AS (...), b AS (...)
        pattern = r"WITH\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+AS|,\s*([a-zA-Z_][a-zA-Z0-9_]*)\s+AS"

        matches = re.findall(pattern, sql, re.IGNORECASE)

        for match in matches:
            name = match[0] or match[1]
            if name:
                registry[name.lower()] = {
                    "line": 0,
                    "body": "N/A (regex fallback)"
                }

    return registry
