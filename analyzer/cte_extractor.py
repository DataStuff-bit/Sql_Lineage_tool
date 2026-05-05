import re
import sqlglot
from sqlglot import exp
from typing import Union


# ═══════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════

def extract_ctes(sql_input: Union[str, exp.Expression, dict]) -> dict:
    """
    Robustly extract all CTEs from a SQL string, parsed expression,
    or pass-through dict.

    Returns:
        {
            "cte_name": {
                "line":    int,       # 1-based line number
                "body":    str,       # CTE body SQL
                "columns": list[str], # explicit column list (if declared)
                "source":  str,       # "parser" | "regex" | "parser+regex"
            },
            ...
        }
    """

    # ── Guard: already extracted ─────────────────────────────
    if isinstance(sql_input, dict):
        return sql_input

    sql    = ""
    parsed = None

    # ── Normalise input ──────────────────────────────────────
    if isinstance(sql_input, str):
        sql = sql_input.strip()
        if not sql:
            return {}
        parsed = _try_parse(sql)

    elif isinstance(sql_input, exp.Expression):
        parsed = sql_input
        sql    = _safe_sql(parsed)

    else:
        # Unknown type — stringify and try
        try:
            sql    = str(sql_input).strip()
            parsed = _try_parse(sql)
        except Exception:
            return {}

    if not sql:
        return {}

    # ── Line-number helper (built once, reused everywhere) ───
    offset_to_line = _build_line_index(sql)

    # ── Parser extraction ────────────────────────────────────
    registry = {}
    if parsed is not None:
        registry = _parser_extract(parsed, sql, offset_to_line)

    # ── Regex extraction ─────────────────────────────────────
    # Always run regex so we can patch missing bodies
    regex_registry = _regex_extract(sql, offset_to_line)

    if not registry:
        # Parser found nothing — use regex entirely
        registry = regex_registry
    else:
        # Patch any empty bodies the parser left behind
        for name, info in registry.items():
            if not info.get("body") and name in regex_registry:
                info["body"]   = regex_registry[name]["body"]
                info["source"] = "parser+regex"

        # Add any CTEs the parser missed but regex found
        for name, info in regex_registry.items():
            if name not in registry:
                registry[name] = info

    return registry


# ═══════════════════════════════════════════════════════════════
# INTERNAL — PARSE HELPERS
# ═══════════════════════════════════════════════════════════════

_DIALECTS = ("snowflake", "tsql", "spark", "bigquery", "postgres", None)


def _try_parse(sql: str) -> "exp.Expression | None":
    """Try multiple dialects and return the first successful parse."""
    for dialect in _DIALECTS:
        try:
            result = sqlglot.parse_one(sql, read=dialect)
            if result is not None:
                return result
        except Exception:
            continue
    return None


def _safe_sql(node: exp.Expression, dialect: str = "snowflake") -> str:
    """Safely convert an expression back to SQL text."""
    try:
        return node.sql(dialect=dialect, pretty=True)
    except Exception:
        try:
            return str(node)
        except Exception:
            return ""


# ═══════════════════════════════════════════════════════════════
# INTERNAL — LINE NUMBER INDEX
# ═══════════════════════════════════════════════════════════════

def _build_line_index(sql: str):
    """
    Returns a closure: offset (int) → line number (1-based).
    Uses binary search on pre-built newline offsets.
    """
    offsets = [0]
    for i, ch in enumerate(sql):
        if ch == "\n":
            offsets.append(i + 1)

    def offset_to_line(offset: int) -> int:
        lo, hi = 0, len(offsets) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if offsets[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1  # 1-based

    return offset_to_line


def _find_cte_line(cte_name: str, sql: str, offset_to_line) -> int:
    """Locate the line where a CTE is defined in raw SQL."""
    patterns = [
        rf"(?:WITH|,)\s+[`\"\[]?{re.escape(cte_name)}[`\"\]]?\s+AS\s*\(",
        rf"\b{re.escape(cte_name)}\b\s+AS\s*\(",
    ]
    for pat in patterns:
        m = re.search(pat, sql, re.IGNORECASE)
        if m:
            return offset_to_line(m.start())
    return 0


# ═══════════════════════════════════════════════════════════════
# INTERNAL — PARSER-BASED EXTRACTION
# ═══════════════════════════════════════════════════════════════

def _parser_extract(parsed: exp.Expression, sql: str, offset_to_line) -> dict:
    """Walk all With nodes and extract CTE metadata via sqlglot AST."""
    registry = {}

    try:
        with_nodes = list(parsed.find_all(exp.With)) or []
    except Exception:
        return registry

    for with_node in with_nodes:
        expressions = getattr(with_node, "expressions", None) or []

        for cte_node in expressions:
            if not isinstance(cte_node, exp.CTE):
                continue

            # ── Name ─────────────────────────────────────────
            try:
                raw_name = cte_node.alias_or_name or ""
            except Exception:
                raw_name = ""

            if not raw_name:
                alias_node = cte_node.args.get("alias")
                if alias_node:
                    raw_name = getattr(alias_node, "name", "") or str(alias_node)

            if not raw_name:
                continue

            name = raw_name.lower().strip('`"[]').strip()
            if not name:
                continue

            # ── Explicit column list ──────────────────────────
            columns: list = []
            try:
                alias_node = cte_node.args.get("alias")
                if alias_node and isinstance(alias_node, exp.TableAlias):
                    col_nodes = alias_node.args.get("columns") or []
                    columns = [
                        col.name
                        for col in col_nodes
                        if hasattr(col, "name") and col.name
                    ]
            except Exception:
                columns = []

            # ── Body SQL ─────────────────────────────────────
            body_node = cte_node.this
            if body_node is None:
                continue

            body_sql = _safe_sql(body_node)

            # ── Line number ───────────────────────────────────
            line = _find_cte_line(raw_name, sql, offset_to_line)

            registry[name] = {
                "line":    line,
                "body":    body_sql,
                "columns": columns,
                "source":  "parser",
            }

    return registry


# ═══════════════════════════════════════════════════════════════
# INTERNAL — REGEX-BASED EXTRACTION
# ═══════════════════════════════════════════════════════════════

def _regex_extract(sql: str, offset_to_line) -> dict:
    """
    Pure-regex fallback.
    Handles: "quoted", [bracketed], `backtick`, plain names,
             nested parens, WITH RECURSIVE, comments.
    """
    registry = {}
    clean    = _strip_comments(sql)

    with_match = re.search(r'\bWITH\b\s*(?:RECURSIVE\s+)?', clean, re.IGNORECASE)
    if not with_match:
        return registry

    pos = with_match.end()

    # Matches:  optional_quote name optional_quote  optional(col,list)  AS  (
    name_pat = re.compile(
        r'\s*(?:"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|([a-zA-Z_]\w*))'
        r'(?:\s*\(([^)]*)\))?'
        r'\s+AS\s*\(',
        re.IGNORECASE,
    )

    _STOP_KEYWORDS = ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'CREATE')

    while pos < len(clean):
        # Skip whitespace and commas
        while pos < len(clean) and clean[pos] in (' ', '\t', '\n', '\r', ','):
            pos += 1

        m = name_pat.match(clean, pos)
        if not m:
            break

        raw_name = (m.group(1) or m.group(2) or m.group(3) or m.group(4) or "").strip()
        if not raw_name:
            break

        col_str = m.group(5) or ""
        columns = [c.strip() for c in col_str.split(",") if c.strip()]
        name    = raw_name.lower()

        open_paren  = m.end() - 1          # position of the '(' after AS
        close_paren = _find_matching_paren(clean, open_paren)
        if close_paren == -1:
            break                           # malformed SQL — stop

        body = clean[open_paren + 1:close_paren].strip()
        line = offset_to_line(m.start())

        registry[name] = {
            "line":    line,
            "body":    body,
            "columns": columns,
            "source":  "regex",
        }

        pos = close_paren + 1

        # Stop when we reach the final query
        peek = clean[pos:].lstrip().upper()
        if not peek or any(peek.startswith(k) for k in _STOP_KEYWORDS):
            break

    return registry


# ═══════════════════════════════════════════════════════════════
# INTERNAL — STRING UTILITIES
# ═══════════════════════════════════════════════════════════════

def _strip_comments(sql: str) -> str:
    """
    Remove -- line comments and /* block comments */
    while preserving content inside string literals.
    """
    result    = []
    i         = 0
    in_single = False
    in_double = False

    while i < len(sql):
        c = sql[i]

        # Track string literal boundaries
        if c == "'" and not in_double:
            in_single = not in_single
            result.append(c); i += 1; continue

        if c == '"' and not in_single:
            in_double = not in_double
            result.append(c); i += 1; continue

        # Inside a string — pass through verbatim
        if in_single or in_double:
            result.append(c); i += 1; continue

        # Line comment
        if sql[i:i+2] == '--':
            while i < len(sql) and sql[i] != '\n':
                i += 1
            result.append('\n')
            continue

        # Block comment
        if sql[i:i+2] == '/*':
            i += 2
            while i < len(sql) - 1 and sql[i:i+2] != '*/':
                i += 1
            i += 2
            result.append(' ')
            continue

        result.append(c)
        i += 1

    return ''.join(result)


def _find_matching_paren(sql: str, start: int) -> int:
    """
    Given the index of '(' at sql[start], return the index of
    its matching ')'. Returns -1 if not found.
    """
    depth     = 0
    i         = start
    in_single = False
    in_double = False

    while i < len(sql):
        c = sql[i]

        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    return i
        i += 1

    return -1  # unmatched