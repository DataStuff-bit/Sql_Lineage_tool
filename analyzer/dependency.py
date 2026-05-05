import sqlglot
from collections import defaultdict
from sqlglot import exp


def build_dependencies(ctes: dict) -> dict:
    """
    Build a dependency map { cte_name: [list of CTEs it depends on] }.
    Works whether ctes values are:
      - exp.Expression objects  (from sqlglot parser)
      - dicts with "body" key   (from our extractor)
      - raw SQL strings
    """
    cte_names = set(ctes.keys())
    deps = {name: [] for name in cte_names}

    for name, value in ctes.items():

        # ── Resolve the body to a parsed Expression ──────────
        parsed_body = _resolve_to_expression(value)
        if parsed_body is None:
            continue

        # ── Find all table references in the body ─────────────
        try:
            referenced = {
                table.name.lower()
                for table in parsed_body.find_all(exp.Table)
                if table.name
            }
        except Exception:
            continue

        # ── Keep only references that are other CTEs ──────────
        deps[name] = [
            ref for ref in referenced
            if ref in cte_names and ref != name
        ]

    return deps


def _resolve_to_expression(value) -> "exp.Expression | None":
    """
    Convert whatever the CTE value is into a sqlglot Expression.

    Handles:
      - exp.Expression  → return as-is
      - dict            → extract "body" key and parse it
      - str             → parse directly
    """
    # Already a parsed expression
    if isinstance(value, exp.Expression):
        return value

    # Dict from our extractor: {"body": "SELECT ...", "line": 5, ...}
    if isinstance(value, dict):
        body = value.get("body", "")
        if not body or body == "N/A (regex fallback)":
            return None
        value = body   # fall through to string parsing

    # Raw SQL string
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return None
        for dialect in ("snowflake", "tsql", "spark", "bigquery", "postgres", None):
            try:
                result = sqlglot.parse_one(value, read=dialect)
                if result is not None:
                    return result
            except Exception:
                continue

    return None