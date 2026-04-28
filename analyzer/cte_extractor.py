import sqlglot

def extract_ctes(parsed):
    ctes = {}
    for cte in parsed.find_all(sqlglot.exp.CTE):
        ctes[cte.alias] = cte.this
    return ctes