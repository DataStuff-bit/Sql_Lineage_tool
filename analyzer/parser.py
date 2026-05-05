import sqlglot
from sqlglot import exp
from typing import Optional


def parse_query(query: str) -> Optional[exp.Expression]:
    """
    Parse a SQL query string into a sqlglot Expression.
    Tries multiple dialects and returns None if all fail.
    """
    if not query or not query.strip():
        return None

    query = query.strip()

    for dialect in ("snowflake", "tsql", "spark", "bigquery", "postgres", None):
        try:
            result = sqlglot.parse_one(query, read=dialect)
            if result is not None:
                return result
        except Exception:
            continue

    return None