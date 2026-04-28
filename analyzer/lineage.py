import sqlglot

def extract_columns(expr):
    columns = []

    for select in expr.find_all(sqlglot.exp.Select):
        for projection in select.expressions:
            alias = projection.alias_or_name
            source_cols = []

            for col in projection.find_all(sqlglot.exp.Column):
                source_cols.append(col.sql())

            columns.append({
                "output": alias,
                "sources": source_cols
            })

    return columns


def build_lineage(ctes, final_expr):
    lineage = {}

    # Process CTEs first
    for name, expr in ctes.items():
        lineage[name] = extract_columns(expr)

    # Final query lineage
    final_lineage = extract_columns(final_expr)

    return lineage, final_lineage