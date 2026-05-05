import sqlglot
from sqlglot import exp


def _resolve_expression(value) -> "exp.Expression | None":
    """Convert dict / string / Expression → parsed Expression."""
    if isinstance(value, exp.Expression):
        return value

    if isinstance(value, dict):
        body = value.get("body", "")
        if not body or body == "N/A (regex fallback)":
            return None
        value = body  # fall through to string parsing

    if isinstance(value, str) and value.strip():
        for dialect in ("snowflake", "tsql", "spark", "bigquery", "postgres", None):
            try:
                result = sqlglot.parse_one(value, read=dialect)
                if result is not None:
                    return result
            except Exception:
                continue

    return None


def extract_columns(expr) -> list:
    """Extract column lineage from a CTE body (any input type)."""
    columns = []

    # ✅ Resolve to Expression first
    parsed = _resolve_expression(expr)
    if parsed is None:
        return columns

    try:
        for select in parsed.find_all(exp.Select):
            for col in select.expressions:
                output  = col.alias_or_name or str(col)
                sources = [
                    t.name
                    for t in col.find_all(exp.Column)
                    if t.name
                ]
                columns.append({
                    "output":  output,
                    "sources": sources,
                })
    except Exception:
        pass

    return columns


def build_lineage(ctes: dict, parsed) -> tuple:
    """Build column lineage for all CTEs and the final query."""
    lineage: dict = {}

    for name, expr in ctes.items():
        lineage[name] = extract_columns(expr)   # ✅ _resolve handles dict

    # Final SELECT lineage
    final_lineage = []
    if parsed is not None:
        final_lineage = extract_columns(parsed)

    return lineage, final_lineage